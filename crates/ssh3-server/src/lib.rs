use std::env;
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
use std::fmt;
#[cfg(unix)]
use std::fs::File as StdFile;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use http::{Request, Response, StatusCode};
#[cfg(unix)]
use nix::pty::{Winsize, openpty};
#[cfg(unix)]
use nix::sys::signal::{self, Signal};
#[cfg(unix)]
use nix::unistd::{Gid, Pid, Uid, User};
use quinn::{Connection, ConnectionError, Endpoint};
use ssh3_auth::{
    AuthError, AuthorizedIdentity, conversation_id_base64, load_authorized_identities_from_paths,
    verify_bearer_token, verify_oidc_identity_token,
};
use ssh3_core::{AcceptedChannel, Channel, ChannelError, ConversationError};
use ssh3_h3::{
    AcceptedServerConversation, BuildConnectRequestError, DatagramDispatchError, SSH3_USER_HEADER,
    SSH3_VERSION_STRING, ServerConnectionDriver, ServerConversationError, is_ssh3_connect,
    response_with_server_header, route_registered_datagram,
};
use ssh3_proto::{
    ChannelRequest, ChannelRequestMessage, ExitStatusRequest, Message, PtyRequest,
    SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, SignalRequest, WindowChangeRequest,
};
use ssh3_quinn::{
    AcceptChannelError, ConfigError, IncomingChannelRouter, OpenChannelError,
    RouteAcceptedChannelError, open_channel, self_signed_server_config,
};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{ChildStdin, Command};

pub type PasswordVerifier = Arc<dyn Fn(&str, &str) -> io::Result<bool> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub cert_subject_alt_names: Vec<String>,
    pub server_header: String,
    pub max_packet_size: u64,
    pub default_datagrams_queue_size: usize,
    pub require_authentication: bool,
    pub enable_password_login: bool,
    pub authorized_identity_paths: Vec<PathBuf>,
    pub default_user: Option<String>,
    pub shell: Option<String>,
    pub password_verifier: Option<PasswordVerifier>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind_addr", &self.bind_addr)
            .field("cert_subject_alt_names", &self.cert_subject_alt_names)
            .field("server_header", &self.server_header)
            .field("max_packet_size", &self.max_packet_size)
            .field(
                "default_datagrams_queue_size",
                &self.default_datagrams_queue_size,
            )
            .field("require_authentication", &self.require_authentication)
            .field("enable_password_login", &self.enable_password_login)
            .field("authorized_identity_paths", &self.authorized_identity_paths)
            .field("default_user", &self.default_user)
            .field("shell", &self.shell)
            .field(
                "password_verifier",
                &self.password_verifier.as_ref().map(|_| "<custom>"),
            )
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 4433)),
            cert_subject_alt_names: vec!["localhost".to_string()],
            server_header: SSH3_VERSION_STRING.to_string(),
            max_packet_size: 30_000,
            default_datagrams_queue_size: 10,
            require_authentication: false,
            enable_password_login: false,
            authorized_identity_paths: Vec::new(),
            default_user: current_username(),
            shell: env::var("SHELL").ok().filter(|shell| !shell.is_empty()),
            password_verifier: None,
        }
    }
}

#[derive(Clone, Debug)]
struct SessionUser {
    username: String,
    home_dir: PathBuf,
    shell: PathBuf,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
}

#[derive(Clone, Debug)]
enum SessionCommand {
    Shell,
    Exec(String),
}

fn current_username() -> Option<String> {
    #[cfg(unix)]
    {
        User::from_uid(Uid::current())
            .ok()
            .flatten()
            .map(|user| user.name)
    }

    #[cfg(not(unix))]
    {
        env::var("USER").ok().or_else(|| env::var("USERNAME").ok())
    }
}

fn extract_query_param(uri: &http::Uri, name: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|entry| {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next()?;
        let value = parts.next().unwrap_or_default();
        (key == name && !value.is_empty()).then(|| value.to_string())
    })
}

fn requested_username(request: &Request<()>, config: &ServerConfig) -> Option<String> {
    request
        .headers()
        .get(SSH3_USER_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| extract_query_param(request.uri(), "user"))
        .or_else(|| config.default_user.clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RequestAuthorization {
    None,
    Basic { username: String, password: String },
    Bearer(String),
}

fn parse_request_authorization(request: &Request<()>) -> RequestAuthorization {
    fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
        let prefix_len = scheme.len();
        (value.len() > prefix_len
            && value[..prefix_len].eq_ignore_ascii_case(scheme)
            && value.as_bytes().get(prefix_len) == Some(&b' '))
        .then(|| value[prefix_len + 1..].trim())
    }

    let Some(value) = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return RequestAuthorization::None;
    };

    if let Some(encoded) = strip_scheme(value, "Basic") {
        let Some(decoded) = BASE64_STANDARD.decode(encoded).ok() else {
            return RequestAuthorization::None;
        };
        let Some(decoded) = String::from_utf8(decoded).ok() else {
            return RequestAuthorization::None;
        };
        let Some((username, password)) = decoded.split_once(':') else {
            return RequestAuthorization::None;
        };
        return RequestAuthorization::Basic {
            username: username.to_string(),
            password: password.to_string(),
        };
    }

    if let Some(token) = strip_scheme(value, "Bearer") {
        if !token.is_empty() {
            return RequestAuthorization::Bearer(token.to_string());
        }
    }

    RequestAuthorization::None
}

#[cfg(unix)]
fn lookup_session_user(username: &str) -> io::Result<SessionUser> {
    let Some(user) = User::from_name(username).map_err(io::Error::from)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unknown user: {username}"),
        ));
    };

    Ok(SessionUser {
        username: user.name,
        home_dir: user.dir,
        shell: if user.shell.as_os_str().is_empty() {
            PathBuf::from("/bin/sh")
        } else {
            user.shell
        },
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
    })
}

#[cfg(not(unix))]
fn lookup_session_user(username: &str) -> io::Result<SessionUser> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let home_dir = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Ok(SessionUser {
        username: username.to_string(),
        home_dir: PathBuf::from(home_dir),
        shell: PathBuf::from(shell),
    })
}

fn resolve_session_user(
    request: &Request<()>,
    authorization: &RequestAuthorization,
    config: &ServerConfig,
) -> io::Result<SessionUser> {
    let username = match authorization {
        RequestAuthorization::Basic { username, .. } if !username.is_empty() => {
            Some(username.clone())
        }
        _ => requested_username(request, config),
    }
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no SSH3 user was requested and no default server user is configured",
        )
    })?;
    lookup_session_user(&username)
}

fn effective_shell(config: &ServerConfig, session_user: &SessionUser) -> PathBuf {
    config
        .shell
        .clone()
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| {
            if session_user.shell.as_os_str().is_empty() {
                PathBuf::from("/bin/sh")
            } else {
                session_user.shell.clone()
            }
        })
}

fn default_authorized_identity_paths(session_user: &SessionUser) -> Vec<PathBuf> {
    vec![
        session_user
            .home_dir
            .join(".ssh3")
            .join("authorized_identities"),
        session_user.home_dir.join(".ssh").join("authorized_keys"),
    ]
}

fn configured_authorized_identity_paths(
    config: &ServerConfig,
    session_user: &SessionUser,
) -> Vec<PathBuf> {
    if config.authorized_identity_paths.is_empty() {
        default_authorized_identity_paths(session_user)
    } else {
        config.authorized_identity_paths.clone()
    }
}

fn should_authenticate(config: &ServerConfig) -> bool {
    config.require_authentication
        || config.enable_password_login
        || !config.authorized_identity_paths.is_empty()
}

#[cfg(target_os = "linux")]
#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(
        key: *const nix::libc::c_char,
        salt: *const nix::libc::c_char,
    ) -> *mut nix::libc::c_char;
}

#[cfg(target_os = "linux")]
fn crypt_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(target_os = "linux")]
fn platform_password_auth_available() -> bool {
    true
}

#[cfg(not(target_os = "linux"))]
fn platform_password_auth_available() -> bool {
    false
}

fn password_auth_available(config: &ServerConfig) -> bool {
    config.password_verifier.is_some() || platform_password_auth_available()
}

#[cfg(target_os = "linux")]
fn default_password_verifier(username: &str, password: &str) -> io::Result<bool> {
    let username = CString::new(username)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "username contains NUL byte"))?;
    let password = CString::new(password)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password contains NUL byte"))?;

    let mut buffer_len = 1024usize;
    loop {
        let mut shadow_entry = std::mem::MaybeUninit::<nix::libc::spwd>::uninit();
        let mut buffer = vec![0u8; buffer_len];
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            nix::libc::getspnam_r(
                username.as_ptr(),
                shadow_entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };

        if status == 0 {
            if result.is_null() {
                return Ok(false);
            }

            let shadow_entry = unsafe { shadow_entry.assume_init() };
            if shadow_entry.sp_pwdp.is_null() {
                return Ok(false);
            }

            let stored_hash = unsafe { CStr::from_ptr(shadow_entry.sp_pwdp) };
            let stored_bytes = stored_hash.to_bytes();
            if stored_bytes.is_empty() || matches!(stored_bytes[0], b'!' | b'*') {
                return Ok(false);
            }

            let computed_hash = {
                // F-21: a panic while holding this process-wide lock must not
                // poison it — that would turn one panicking thread into a
                // process-wide password-auth outage. Recover the guard even
                // from a poisoned lock: the critical section holds no
                // invariant to repair (crypt(3) works on a static buffer).
                let _guard = crypt_lock()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let computed = unsafe { crypt(password.as_ptr(), shadow_entry.sp_pwdp) };
                if computed.is_null() {
                    return Err(io::Error::last_os_error());
                }
                unsafe { CStr::from_ptr(computed).to_owned() }
            };

            return Ok(computed_hash.as_c_str().to_bytes() == stored_bytes);
        }

        if status == nix::libc::ERANGE && buffer_len < 1 << 20 {
            buffer_len *= 2;
            continue;
        }

        return Err(io::Error::from_raw_os_error(status));
    }
}

#[cfg(not(target_os = "linux"))]
fn default_password_verifier(_username: &str, _password: &str) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "password authentication is not supported on this platform",
    ))
}

fn verify_password(config: &ServerConfig, username: &str, password: &str) -> io::Result<bool> {
    if let Some(verifier) = config.password_verifier.as_ref() {
        return verifier(username, password);
    }
    default_password_verifier(username, password)
}

async fn authorize_request(
    authorization: &RequestAuthorization,
    session_user: &SessionUser,
    conversation_id: &[u8; 32],
    config: &ServerConfig,
) -> Result<bool, AuthError> {
    if !should_authenticate(config) {
        return Ok(true);
    }

    match authorization {
        RequestAuthorization::Basic { username, password } => {
            if !config.enable_password_login || username != &session_user.username {
                return Ok(false);
            }
            verify_password(config, username, password).map_err(AuthError::from)
        }
        RequestAuthorization::Bearer(token) => {
            let identities = load_authorized_identities_from_paths(
                &configured_authorized_identity_paths(config, session_user),
            )?;
            if identities.is_empty() {
                return Ok(false);
            }

            for identity in &identities {
                match identity {
                    AuthorizedIdentity::PublicKey(public_key) => {
                        if verify_bearer_token(
                            public_key,
                            token,
                            &session_user.username,
                            conversation_id,
                        )
                        .is_ok()
                        {
                            return Ok(true);
                        }
                    }
                    AuthorizedIdentity::Oidc(oidc_identity) => {
                        let expected_nonce = conversation_id_base64(conversation_id);
                        if verify_oidc_identity_token(
                            oidc_identity,
                            token,
                            Some(expected_nonce.as_str()),
                        )
                        .await
                        .is_ok()
                        {
                            return Ok(true);
                        }
                    }
                }
            }

            Ok(false)
        }
        RequestAuthorization::None => Ok(false),
    }
}

#[cfg(unix)]
fn login_shell_arg0(shell: &Path) -> String {
    let file_name = shell
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("sh");
    format!("-{file_name}")
}

fn configure_process(
    process: &mut Command,
    config: &ServerConfig,
    session_user: &SessionUser,
    command: &SessionCommand,
    agent_socket_path: Option<&Path>,
) {
    let shell = effective_shell(config, session_user);
    process.kill_on_drop(true);
    process.env("HOME", &session_user.home_dir);
    process.env("USER", &session_user.username);
    process.env("LOGNAME", &session_user.username);
    process.env("SHELL", &shell);
    if let Some(agent_socket_path) = agent_socket_path {
        process.env("SSH_AUTH_SOCK", agent_socket_path);
    }
    process.env(
        "PATH",
        env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin:/usr/sbin:/sbin".to_string()),
    );
    if session_user.home_dir.is_dir() {
        process.current_dir(&session_user.home_dir);
    }

    #[cfg(unix)]
    {
        if session_user.uid != Uid::current().as_raw()
            || session_user.gid != Gid::current().as_raw()
        {
            process.uid(session_user.uid);
            process.gid(session_user.gid);
        }
        if matches!(command, SessionCommand::Shell) {
            process.arg0(login_shell_arg0(&shell));
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SessionPtySize {
    char_width: u16,
    char_height: u16,
    pixel_width: u16,
    pixel_height: u16,
}

impl SessionPtySize {
    fn from_pty_request(request: &PtyRequest) -> Self {
        Self {
            char_width: clamp_u64_to_u16(request.char_width),
            char_height: clamp_u64_to_u16(request.char_height),
            pixel_width: clamp_u64_to_u16(request.pixel_width),
            pixel_height: clamp_u64_to_u16(request.pixel_height),
        }
    }

    fn from_window_change(request: &WindowChangeRequest) -> Self {
        Self {
            char_width: clamp_u64_to_u16(request.char_width),
            char_height: clamp_u64_to_u16(request.char_height),
            pixel_width: clamp_u64_to_u16(request.pixel_width),
            pixel_height: clamp_u64_to_u16(request.pixel_height),
        }
    }

    #[cfg(unix)]
    fn to_winsize(self) -> Winsize {
        Winsize {
            ws_row: self.char_height,
            ws_col: self.char_width,
            ws_xpixel: self.pixel_width,
            ws_ypixel: self.pixel_height,
        }
    }
}

#[derive(Clone, Debug)]
struct PendingPty {
    term: Option<String>,
    size: SessionPtySize,
}

#[cfg(unix)]
struct AgentForwarding {
    socket_path: PathBuf,
    socket_dir: PathBuf,
    listener_task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl AgentForwarding {
    fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(unix)]
impl Drop for AgentForwarding {
    fn drop(&mut self) {
        self.listener_task.abort();
        let _ = std::fs::remove_file(&self.socket_path);
        let _ = std::fs::remove_dir(&self.socket_dir);
    }
}

enum SessionInput {
    Pipe(ChildStdin),
    Pty(TokioFile),
}

impl SessionInput {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), ServerError> {
        match self {
            Self::Pipe(stdin) => {
                stdin.write_all(data).await?;
                stdin.flush().await?;
            }
            Self::Pty(pty) => {
                pty.write_all(data).await?;
                pty.flush().await?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
struct PtyController {
    master: StdFile,
}

#[cfg(unix)]
impl PtyController {
    fn resize(&self, size: SessionPtySize) -> io::Result<()> {
        let winsize = size.to_winsize();
        let result =
            unsafe { nix::libc::ioctl(self.master.as_raw_fd(), nix::libc::TIOCSWINSZ, &winsize) };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

struct RunningSession {
    input: SessionInput,
    child_id: Option<u32>,
    #[cfg(unix)]
    pty: Option<PtyController>,
}

impl RunningSession {
    async fn write_input(&mut self, data: &[u8]) -> Result<(), ServerError> {
        self.input.write_all(data).await
    }

    fn apply_window_change(&mut self, size: SessionPtySize) -> Result<(), ServerError> {
        #[cfg(unix)]
        {
            if let Some(pty) = &self.pty {
                pty.resize(size)?;
                return Ok(());
            }
        }
        Err(ServerError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "window-change requires a PTY-backed session",
        )))
    }

    fn send_signal(&self, request: &SignalRequest) -> Result<(), ServerError> {
        #[cfg(not(unix))]
        {
            let _ = request;
            return Err(ServerError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "signal forwarding is not supported on this platform",
            )));
        }

        #[cfg(unix)]
        let signal = parse_signal_request(request).ok_or_else(|| {
            ServerError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unsupported signal: {}",
                    String::from_utf8_lossy(&request.signal_name_without_sig)
                ),
            ))
        })?;
        let Some(child_id) = self.child_id else {
            return Err(ServerError::Io(io::Error::other(
                "running session does not have a child pid",
            )));
        };

        #[cfg(unix)]
        {
            let pid = child_id as i32;
            if self.pty.is_some() {
                signal::kill(Pid::from_raw(-pid), signal).map_err(io::Error::from)?;
            } else {
                signal::kill(Pid::from_raw(pid), signal).map_err(io::Error::from)?;
            }
            return Ok(());
        }

        #[allow(unreachable_code)]
        Err(ServerError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "signal forwarding is not supported on this platform",
        )))
    }
}

#[derive(Debug)]
pub enum ServerError {
    Config(ConfigError),
    Auth(AuthError),
    Io(io::Error),
    Http(http::Error),
    H3Connection(h3::error::ConnectionError),
    BuildResponse(BuildConnectRequestError),
    Connection(ConnectionError),
    OpenChannel(OpenChannelError),
    AcceptChannel(AcceptChannelError),
    RouteAcceptedChannel(RouteAcceptedChannelError),
    ServerConversation(ServerConversationError),
    DatagramDispatch(DatagramDispatchError),
    Conversation(ConversationError),
    Channel(ChannelError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "{err}"),
            Self::Auth(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Http(err) => write!(f, "{err}"),
            Self::H3Connection(err) => write!(f, "{err}"),
            Self::BuildResponse(err) => write!(f, "{err}"),
            Self::Connection(err) => write!(f, "{err}"),
            Self::OpenChannel(err) => write!(f, "{err}"),
            Self::AcceptChannel(err) => write!(f, "{err}"),
            Self::RouteAcceptedChannel(err) => write!(f, "{err}"),
            Self::ServerConversation(err) => write!(f, "{err}"),
            Self::DatagramDispatch(err) => write!(f, "{err}"),
            Self::Conversation(err) => write!(f, "{err}"),
            Self::Channel(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            Self::Auth(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::Http(err) => Some(err),
            Self::H3Connection(err) => Some(err),
            Self::BuildResponse(err) => Some(err),
            Self::Connection(err) => Some(err),
            Self::OpenChannel(err) => Some(err),
            Self::AcceptChannel(err) => Some(err),
            Self::RouteAcceptedChannel(err) => Some(err),
            Self::ServerConversation(err) => Some(err),
            Self::DatagramDispatch(err) => Some(err),
            Self::Conversation(err) => Some(err),
            Self::Channel(err) => Some(err),
        }
    }
}

impl From<ConfigError> for ServerError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<io::Error> for ServerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<AuthError> for ServerError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

impl From<http::Error> for ServerError {
    fn from(value: http::Error) -> Self {
        Self::Http(value)
    }
}

impl From<h3::error::ConnectionError> for ServerError {
    fn from(value: h3::error::ConnectionError) -> Self {
        Self::H3Connection(value)
    }
}

impl From<BuildConnectRequestError> for ServerError {
    fn from(value: BuildConnectRequestError) -> Self {
        Self::BuildResponse(value)
    }
}

impl From<ConnectionError> for ServerError {
    fn from(value: ConnectionError) -> Self {
        Self::Connection(value)
    }
}

impl From<OpenChannelError> for ServerError {
    fn from(value: OpenChannelError) -> Self {
        Self::OpenChannel(value)
    }
}

impl From<AcceptChannelError> for ServerError {
    fn from(value: AcceptChannelError) -> Self {
        Self::AcceptChannel(value)
    }
}

impl From<RouteAcceptedChannelError> for ServerError {
    fn from(value: RouteAcceptedChannelError) -> Self {
        Self::RouteAcceptedChannel(value)
    }
}

impl From<ServerConversationError> for ServerError {
    fn from(value: ServerConversationError) -> Self {
        Self::ServerConversation(value)
    }
}

impl From<DatagramDispatchError> for ServerError {
    fn from(value: DatagramDispatchError) -> Self {
        Self::DatagramDispatch(value)
    }
}

impl From<ConversationError> for ServerError {
    fn from(value: ConversationError) -> Self {
        Self::Conversation(value)
    }
}

impl From<ChannelError> for ServerError {
    fn from(value: ChannelError) -> Self {
        Self::Channel(value)
    }
}

fn validate_server_config(config: &ServerConfig) -> Result<(), ServerError> {
    if config.enable_password_login && !password_auth_available(config) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "password authentication is not supported on this platform",
        )
        .into());
    }
    Ok(())
}

pub async fn run_with_self_signed(config: ServerConfig) -> Result<(), ServerError> {
    validate_server_config(&config)?;
    let (server_config, _certificate) =
        self_signed_server_config(config.cert_subject_alt_names.clone())?;
    let endpoint = Endpoint::server(server_config, config.bind_addr)?;
    serve_endpoint(endpoint, config).await
}

pub async fn serve_endpoint(endpoint: Endpoint, config: ServerConfig) -> Result<(), ServerError> {
    validate_server_config(&config)?;
    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    if let Err(err) = serve_connection(connection, config).await {
                        if !is_benign_server_error(&err) {
                            eprintln!("ssh3-server connection error: {err}");
                        }
                    }
                }
                Err(err) => {
                    if !is_benign_connection_error(&err) {
                        eprintln!("ssh3-server accept error: {err}");
                    }
                }
            }
        });
    }
    Ok(())
}

pub async fn serve_connection(
    connection: Connection,
    config: ServerConfig,
) -> Result<(), ServerError> {
    validate_server_config(&config)?;
    let mut driver = ServerConnectionDriver::new(connection.clone()).await?;
    let Some(accepted) = driver
        .accept_conversation(config.max_packet_size, config.default_datagrams_queue_size)
        .await?
    else {
        return Ok(());
    };

    handle_conversation(
        accepted,
        connection,
        driver.channel_router().clone(),
        config,
    )
    .await
}

async fn route_datagrams(
    connection: Connection,
    channel_router: Arc<IncomingChannelRouter>,
) -> Result<(), DatagramDispatchError> {
    loop {
        let datagram = connection.read_datagram().await?;
        let _ = route_registered_datagram(channel_router.as_ref(), &datagram).await?;
    }
}

async fn handle_conversation(
    mut accepted: AcceptedServerConversation,
    connection: Connection,
    channel_router: Arc<IncomingChannelRouter>,
    config: ServerConfig,
) -> Result<(), ServerError> {
    let control_stream_id = accepted.conversation.control_stream_id();
    let result = async {
        if !is_ssh3_connect(&accepted.request) {
            accepted
                .control_stream
                .send_response(Response::builder().status(StatusCode::NOT_FOUND).body(())?)
                .await
                .map_err(ServerConversationError::from)?;
            accepted
                .control_stream
                .finish()
                .await
                .map_err(ServerConversationError::from)?;
            return Ok(());
        }

        let authorization = parse_request_authorization(&accepted.request);
        let session_user = match resolve_session_user(&accepted.request, &authorization, &config) {
            Ok(session_user) => session_user,
            Err(_) => {
                accepted
                    .control_stream
                    .send_response(
                        Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body(())?,
                    )
                    .await
                    .map_err(ServerConversationError::from)?;
                accepted
                    .control_stream
                    .finish()
                    .await
                    .map_err(ServerConversationError::from)?;
                return Ok(());
            }
        };
        if !authorize_request(
            &authorization,
            &session_user,
            &accepted.conversation.conversation_id(),
            &config,
        )
        .await?
        {
            accepted
                .control_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(())?,
                )
                .await
                .map_err(ServerConversationError::from)?;
            accepted
                .control_stream
                .finish()
                .await
                .map_err(ServerConversationError::from)?;
            return Ok(());
        }

        accepted
            .control_stream
            .send_response(response_with_server_header(
                StatusCode::OK,
                &config.server_header,
            )?)
            .await
            .map_err(ServerConversationError::from)?;

        let channels_task = tokio::spawn({
            let channel_router = channel_router.clone();
            let connection = connection.clone();
            async move {
                match channel_router
                    .accept_and_route_channels_forever(connection)
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(err) if is_benign_route_error(&err) => Ok(()),
                    Err(err) => Err(ServerError::RouteAcceptedChannel(err)),
                }
            }
        });

        let datagrams_task = tokio::spawn({
            let channel_router = channel_router.clone();
            let connection = connection.clone();
            async move {
                match route_datagrams(connection, channel_router).await {
                    Ok(()) => Ok(()),
                    Err(err) if is_benign_datagram_error(&err) => Ok(()),
                    Err(err) => Err(ServerError::DatagramDispatch(err)),
                }
            }
        });

        loop {
            tokio::select! {
                _ = connection.closed() => break,
                accepted_channel = accepted.conversation.accept_channel_with_metadata() => {
                    let accepted_channel = accepted_channel?;
                    let config = config.clone();
                    let connection = connection.clone();
                    let conversation = accepted.conversation.clone();
                    let session_user = session_user.clone();
                    tokio::spawn(async move {
                        if let Err(err) = handle_accepted_channel(
                            accepted_channel,
                            conversation,
                            connection,
                            config,
                            session_user,
                        )
                        .await
                        {
                            if !is_benign_server_error(&err) {
                                eprintln!("ssh3-server channel error: {err}");
                            }
                        }
                    });
                }
            }
        }

        let _ = channels_task.await;
        let _ = datagrams_task.await;

        Ok(())
    }
    .await;

    channel_router.unregister_conversation(control_stream_id);
    result
}

async fn handle_accepted_channel(
    accepted_channel: AcceptedChannel,
    conversation: Arc<ssh3_core::Conversation>,
    connection: Connection,
    config: ServerConfig,
    session_user: SessionUser,
) -> Result<(), ServerError> {
    match accepted_channel {
        AcceptedChannel::Channel(channel) => {
            handle_plain_channel(channel, conversation, connection, config, session_user).await
        }
        AcceptedChannel::UdpForwarding {
            channel,
            remote_addr,
        } => handle_udp_forwarding(channel, remote_addr, connection).await,
        AcceptedChannel::TcpForwarding {
            channel,
            remote_addr,
        } => handle_tcp_forwarding(channel, remote_addr, connection).await,
    }
}

async fn handle_plain_channel(
    channel: Arc<Channel>,
    conversation: Arc<ssh3_core::Conversation>,
    connection: Connection,
    config: ServerConfig,
    session_user: SessionUser,
) -> Result<(), ServerError> {
    if channel.channel_type() == b"session" {
        handle_session_channel(channel, conversation, connection, config, session_user).await
    } else {
        write_stderr(
            channel.as_ref(),
            format!(
                "unsupported channel type: {}\n",
                String::from_utf8_lossy(channel.channel_type())
            )
            .as_bytes(),
        )
        .await?;
        channel.close().await?;
        Ok(())
    }
}

async fn handle_session_channel(
    channel: Arc<Channel>,
    conversation: Arc<ssh3_core::Conversation>,
    connection: Connection,
    config: ServerConfig,
    session_user: SessionUser,
) -> Result<(), ServerError> {
    let mut pending_pty: Option<PendingPty> = None;
    #[cfg(unix)]
    let mut agent_forwarding: Option<AgentForwarding> = None;
    let mut session: Option<RunningSession> = None;

    loop {
        let message = channel.next_message().await?;
        match message {
            Message::ChannelRequest(request) => match request.request {
                ChannelRequest::Pty(pty) => {
                    if session.is_some() {
                        write_stderr(
                            channel.as_ref(),
                            b"cannot request a PTY after the session has started\n",
                        )
                        .await?;
                    } else {
                        pending_pty = Some(PendingPty {
                            term: ssh_bytes_to_string(&pty.term),
                            size: SessionPtySize::from_pty_request(&pty),
                        });
                    }
                }
                ChannelRequest::Shell => {
                    if session.is_none() {
                        session = Some(
                            spawn_session_process(
                                channel.clone(),
                                &config,
                                &session_user,
                                pending_pty.clone(),
                                {
                                    #[cfg(unix)]
                                    {
                                        agent_forwarding.as_ref().map(AgentForwarding::socket_path)
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        None
                                    }
                                },
                                SessionCommand::Shell,
                            )
                            .await?,
                        );
                    } else {
                        write_stderr(channel.as_ref(), b"session is already running\n").await?;
                    }
                }
                ChannelRequest::Exec(exec) => {
                    if session.is_none() {
                        session = Some(
                            spawn_session_process(
                                channel.clone(),
                                &config,
                                &session_user,
                                pending_pty.clone(),
                                {
                                    #[cfg(unix)]
                                    {
                                        agent_forwarding.as_ref().map(AgentForwarding::socket_path)
                                    }
                                    #[cfg(not(unix))]
                                    {
                                        None
                                    }
                                },
                                SessionCommand::Exec(
                                    ssh_bytes_to_string(&exec.command).unwrap_or_default(),
                                ),
                            )
                            .await?,
                        );
                    } else {
                        write_stderr(channel.as_ref(), b"session is already running\n").await?;
                    }
                }
                ChannelRequest::Signal(signal) => {
                    if let Some(session) = session.as_ref() {
                        if let Err(err) = session.send_signal(&signal) {
                            write_stderr(channel.as_ref(), format!("{err}\n").as_bytes()).await?;
                        }
                    } else {
                        write_stderr(
                            channel.as_ref(),
                            b"cannot signal a session before it has started\n",
                        )
                        .await?;
                    }
                }
                ChannelRequest::WindowChange(window_change) => {
                    let size = SessionPtySize::from_window_change(&window_change);
                    if let Some(session) = session.as_mut() {
                        if let Err(err) = session.apply_window_change(size) {
                            write_stderr(channel.as_ref(), format!("{err}\n").as_bytes()).await?;
                        }
                    } else if let Some(pending_pty) = pending_pty.as_mut() {
                        pending_pty.size = size;
                    } else {
                        write_stderr(
                            channel.as_ref(),
                            b"window-change requires a pending or running PTY session\n",
                        )
                        .await?;
                    }
                }
                other => {
                    write_stderr(
                        channel.as_ref(),
                        format!("unsupported session request: {other:?}\n").as_bytes(),
                    )
                    .await?;
                }
            },
            Message::Data(message) => {
                if message.data_type != SSH_EXTENDED_DATA_NONE {
                    write_stderr(channel.as_ref(), b"unsupported extended data message\n").await?;
                    continue;
                }
                if let Some(session) = session.as_mut() {
                    session.write_input(&message.data).await?;
                } else if message.data == b"forward-agent" {
                    #[cfg(unix)]
                    {
                        if agent_forwarding.is_none() {
                            agent_forwarding = Some(
                                open_agent_socket_and_forward_agent(
                                    conversation.clone(),
                                    connection.clone(),
                                    &config,
                                    &session_user,
                                )
                                .await?,
                            );
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        write_stderr(
                            channel.as_ref(),
                            b"agent forwarding is not supported on this platform\n",
                        )
                        .await?;
                    }
                } else {
                    write_stderr(
                        channel.as_ref(),
                        b"cannot send session data before the session has started\n",
                    )
                    .await?;
                }
            }
            _ => {}
        }
    }
}

async fn spawn_session_process(
    channel: Arc<Channel>,
    config: &ServerConfig,
    session_user: &SessionUser,
    pending_pty: Option<PendingPty>,
    agent_socket_path: Option<&Path>,
    command: SessionCommand,
) -> Result<RunningSession, ServerError> {
    #[cfg(unix)]
    if let Some(pending_pty) = pending_pty {
        return spawn_pty_session_process(
            channel,
            config,
            session_user,
            pending_pty,
            agent_socket_path,
            command,
        )
        .await;
    }

    #[cfg(not(unix))]
    if pending_pty.is_some() {
        return Err(ServerError::Io(io::Error::new(
            io::ErrorKind::Unsupported,
            "PTY requests are not supported on this platform",
        )));
    }

    spawn_pipe_session_process(channel, config, session_user, agent_socket_path, command).await
}

async fn spawn_pipe_session_process(
    channel: Arc<Channel>,
    config: &ServerConfig,
    session_user: &SessionUser,
    agent_socket_path: Option<&Path>,
    command: SessionCommand,
) -> Result<RunningSession, ServerError> {
    let shell = effective_shell(config, session_user);
    let mut process = Command::new(&shell);
    if let SessionCommand::Exec(command) = &command {
        process.arg("-c").arg(command);
    }
    configure_process(
        &mut process,
        config,
        session_user,
        &command,
        agent_socket_path,
    );
    process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = process.spawn()?;
    let child_id = child.id();
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ServerError::Io(io::Error::other("spawned process did not expose stdin")))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdout_task = tokio::spawn(pump_process_output(
        stdout,
        channel.clone(),
        SSH_EXTENDED_DATA_NONE,
    ));
    let stderr_task = tokio::spawn(pump_process_output(
        stderr,
        channel.clone(),
        SSH_EXTENDED_DATA_STDERR,
    ));

    tokio::spawn(async move {
        let status = child.wait().await;
        let _ = stdout_task.await;
        let _ = stderr_task.await;

        let exit_status = status
            .ok()
            .and_then(|status| status.code())
            .unwrap_or(1)
            .max(0) as u64;
        let _ = channel
            .send_request(ChannelRequestMessage {
                want_reply: false,
                request: ChannelRequest::ExitStatus(ExitStatusRequest { exit_status }),
            })
            .await;
    });

    Ok(RunningSession {
        input: SessionInput::Pipe(stdin),
        child_id,
        #[cfg(unix)]
        pty: None,
    })
}

#[cfg(unix)]
async fn spawn_pty_session_process(
    channel: Arc<Channel>,
    config: &ServerConfig,
    session_user: &SessionUser,
    pending_pty: PendingPty,
    agent_socket_path: Option<&Path>,
    command: SessionCommand,
) -> Result<RunningSession, ServerError> {
    let openpty = openpty(Some(&pending_pty.size.to_winsize()), None).map_err(io::Error::from)?;
    let master = StdFile::from(openpty.master);
    let slave = StdFile::from(openpty.slave);

    let shell = effective_shell(config, session_user);
    let mut process = Command::new(&shell);
    if let SessionCommand::Exec(command) = &command {
        process.arg("-c").arg(command);
    }
    configure_process(
        &mut process,
        config,
        session_user,
        &command,
        agent_socket_path,
    );
    process.kill_on_drop(true);
    if let Some(term) = &pending_pty.term {
        process.env("TERM", term);
    }

    let slave_fd = slave.as_raw_fd();
    process
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));
    unsafe {
        process.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = process.spawn()?;
    drop(slave);

    let child_id = child.id();
    let input = TokioFile::from_std(master.try_clone()?);
    let output = TokioFile::from_std(master.try_clone()?);
    let controller = PtyController { master };

    let output_task = tokio::spawn(pump_process_output(
        Some(output),
        channel.clone(),
        SSH_EXTENDED_DATA_NONE,
    ));
    tokio::spawn(async move {
        let status = child.wait().await;
        let _ = output_task.await;

        let exit_status = status
            .ok()
            .and_then(|status| status.code())
            .unwrap_or(1)
            .max(0) as u64;
        let _ = channel
            .send_request(ChannelRequestMessage {
                want_reply: false,
                request: ChannelRequest::ExitStatus(ExitStatusRequest { exit_status }),
            })
            .await;
    });

    Ok(RunningSession {
        input: SessionInput::Pty(input),
        child_id,
        pty: Some(controller),
    })
}

#[cfg(unix)]
fn new_agent_socket_paths() -> io::Result<(PathBuf, PathBuf)> {
    let unique = format!(
        "ssh3-agent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let socket_dir = env::temp_dir().join(unique);
    std::fs::create_dir(&socket_dir)?;
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))?;
    let socket_path = socket_dir.join(format!("agent.{}", std::process::id()));
    Ok((socket_dir, socket_path))
}

#[cfg(unix)]
fn prepare_agent_socket_permissions(
    socket_dir: &Path,
    socket_path: &Path,
    session_user: &SessionUser,
) -> io::Result<()> {
    std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    if session_user.uid != Uid::current().as_raw() || session_user.gid != Gid::current().as_raw() {
        nix::unistd::chown(
            socket_dir,
            Some(Uid::from_raw(session_user.uid)),
            Some(Gid::from_raw(session_user.gid)),
        )
        .map_err(io::Error::from)?;
        nix::unistd::chown(
            socket_path,
            Some(Uid::from_raw(session_user.uid)),
            Some(Gid::from_raw(session_user.gid)),
        )
        .map_err(io::Error::from)?;
    }

    Ok(())
}

#[cfg(unix)]
async fn handle_agent_socket_conn(
    stream: UnixStream,
    conversation: Arc<ssh3_core::Conversation>,
    connection: Connection,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> Result<(), ServerError> {
    let channel = open_channel(
        conversation.as_ref(),
        &connection,
        b"agent-connection".to_vec(),
        max_packet_size,
        default_datagrams_queue_size,
    )
    .await?;
    channel.maybe_send_header().await?;
    channel.wait_for_confirmation().await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut to_socket = tokio::spawn({
        let channel = channel.clone();
        async move {
            loop {
                let message = channel.next_message().await?;
                if let Message::Data(data) = message
                    && data.data_type == SSH_EXTENDED_DATA_NONE
                {
                    writer.write_all(&data.data).await?;
                    writer.flush().await?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), ServerError>(())
        }
    });

    let mut from_socket = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    let _ = channel.close().await;
                    return Ok::<(), ServerError>(());
                }
                channel
                    .write_data(&buf[..n], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
        }
    });

    tokio::select! {
        result = &mut to_socket => {
            from_socket.abort();
            let _ = channel.close().await;
            result.map_err(|err| ServerError::Io(io::Error::other(err.to_string())))?
        }
        result = &mut from_socket => {
            to_socket.abort();
            let _ = channel.close().await;
            result.map_err(|err| ServerError::Io(io::Error::other(err.to_string())))?
        }
    }
}

#[cfg(unix)]
async fn open_agent_socket_and_forward_agent(
    conversation: Arc<ssh3_core::Conversation>,
    connection: Connection,
    config: &ServerConfig,
    session_user: &SessionUser,
) -> Result<AgentForwarding, ServerError> {
    let (socket_dir, socket_path) = new_agent_socket_paths()?;
    let listener = UnixListener::bind(&socket_path)?;
    prepare_agent_socket_permissions(&socket_dir, &socket_path, session_user)?;

    let listener_task = tokio::spawn({
        let conversation = conversation.clone();
        let connection = connection.clone();
        let max_packet_size = config.max_packet_size;
        let default_datagrams_queue_size = config.default_datagrams_queue_size;
        async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(err) => {
                        eprintln!("ssh3-server agent socket accept error: {err}");
                        return;
                    }
                };
                let conversation = conversation.clone();
                let connection = connection.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_agent_socket_conn(
                        stream,
                        conversation,
                        connection,
                        max_packet_size,
                        default_datagrams_queue_size,
                    )
                    .await
                    {
                        if !is_benign_server_error(&err) {
                            eprintln!("ssh3-server agent forwarding error: {err}");
                        }
                    }
                });
            }
        }
    });

    Ok(AgentForwarding {
        socket_path,
        socket_dir,
        listener_task,
    })
}

async fn pump_process_output<R>(
    reader: Option<R>,
    channel: Arc<Channel>,
    data_type: u64,
) -> Result<(), ServerError>
where
    R: AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return Ok(());
    };

    let mut buf = vec![
        0;
        usize::try_from(channel.max_packet_size())
            .unwrap_or(30_000)
            .max(1)
    ];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        channel.write_data(&buf[..n], data_type).await?;
    }
}

async fn handle_udp_forwarding(
    channel: Arc<Channel>,
    remote_addr: SocketAddr,
    connection: Connection,
) -> Result<(), ServerError> {
    let bind_addr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(remote_addr).await?;

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), ServerError>(()),
                    datagram = channel.receive_datagram() => {
                        socket.send(&datagram).await?;
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let socket = socket.clone();
        let connection = connection.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), ServerError>(()),
                    result = socket.recv(&mut buf) => {
                        let n = result?;
                        channel.send_datagram(buf[..n].to_vec()).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}

async fn handle_tcp_forwarding(
    channel: Arc<Channel>,
    remote_addr: SocketAddr,
    connection: Connection,
) -> Result<(), ServerError> {
    let stream = TcpStream::connect(remote_addr).await?;
    let (mut reader, mut writer) = stream.into_split();

    let to_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        async move {
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), ServerError>(()),
                    message = channel.next_message() => {
                        let message = message?;
                        if let Message::Data(data) = message
                            && data.data_type == SSH_EXTENDED_DATA_NONE
                        {
                            writer.write_all(&data.data).await?;
                            writer.flush().await?;
                        }
                    }
                }
            }
        }
    });

    let from_socket = tokio::spawn({
        let channel = channel.clone();
        let connection = connection.clone();
        async move {
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                tokio::select! {
                    _ = connection.closed() => return Ok::<(), ServerError>(()),
                    read = reader.read(&mut buf) => {
                        let n = read?;
                        if n == 0 {
                            return Ok(());
                        }
                        channel.write_data(&buf[..n], SSH_EXTENDED_DATA_NONE).await?;
                    }
                }
            }
        }
    });

    let _ = to_socket.await;
    let _ = from_socket.await;
    Ok(())
}

async fn write_stderr(channel: &Channel, message: &[u8]) -> Result<(), ServerError> {
    channel
        .write_data(message, SSH_EXTENDED_DATA_STDERR)
        .await
        .map(|_| ())
        .map_err(ServerError::from)
}

fn clamp_u64_to_u16(value: u64) -> u16 {
    value.min(u16::MAX as u64) as u16
}

fn ssh_bytes_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

#[cfg(unix)]
fn parse_signal_request(request: &SignalRequest) -> Option<Signal> {
    let signal_name =
        String::from_utf8_lossy(&request.signal_name_without_sig).to_ascii_uppercase();
    let signal_name = signal_name
        .strip_prefix("SIG")
        .unwrap_or(signal_name.as_str());
    match signal_name {
        "ABRT" | "IOT" => Some(Signal::SIGABRT),
        "ALRM" => Some(Signal::SIGALRM),
        "BUS" => Some(Signal::SIGBUS),
        "CHLD" | "CLD" => Some(Signal::SIGCHLD),
        "CONT" => Some(Signal::SIGCONT),
        "FPE" => Some(Signal::SIGFPE),
        "HUP" => Some(Signal::SIGHUP),
        "ILL" => Some(Signal::SIGILL),
        "INT" => Some(Signal::SIGINT),
        "PIPE" => Some(Signal::SIGPIPE),
        "QUIT" => Some(Signal::SIGQUIT),
        "SEGV" => Some(Signal::SIGSEGV),
        "STOP" => Some(Signal::SIGSTOP),
        "TERM" => Some(Signal::SIGTERM),
        "TRAP" => Some(Signal::SIGTRAP),
        "TSTP" => Some(Signal::SIGTSTP),
        "TTIN" => Some(Signal::SIGTTIN),
        "TTOU" => Some(Signal::SIGTTOU),
        "USR1" => Some(Signal::SIGUSR1),
        "USR2" => Some(Signal::SIGUSR2),
        "WINCH" => Some(Signal::SIGWINCH),
        "XCPU" => Some(Signal::SIGXCPU),
        "XFSZ" => Some(Signal::SIGXFSZ),
        _ => None,
    }
}

fn is_benign_connection_error(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::ApplicationClosed(..)
            | ConnectionError::ConnectionClosed(..)
            | ConnectionError::LocallyClosed
            | ConnectionError::TimedOut
    )
}

fn is_benign_io_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    ) {
        return true;
    }

    if error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ConnectionError>())
        .is_some_and(is_benign_connection_error)
    {
        return true;
    }

    let message = error.to_string().to_ascii_lowercase();
    message.contains("connection lost")
        || message.contains("closed stream")
        || message.contains("connection closed")
}

fn is_benign_channel_error(error: &ChannelError) -> bool {
    matches!(error, ChannelError::Io(error) if is_benign_io_error(error))
}

fn is_benign_conversation_error(error: &ConversationError) -> bool {
    matches!(error, ConversationError::Channel(error) if is_benign_channel_error(error))
}

fn is_benign_open_channel_error(error: &OpenChannelError) -> bool {
    match error {
        OpenChannelError::Connection(error) => is_benign_connection_error(error),
        OpenChannelError::Conversation(error) => is_benign_conversation_error(error),
    }
}

fn is_benign_accept_channel_error(error: &AcceptChannelError) -> bool {
    matches!(error, AcceptChannelError::Connection(error) if is_benign_connection_error(error))
}

fn is_benign_route_error(error: &RouteAcceptedChannelError) -> bool {
    matches!(
        error,
        RouteAcceptedChannelError::Accept(AcceptChannelError::Connection(error))
            if is_benign_connection_error(error)
    )
}

fn is_benign_datagram_error(error: &DatagramDispatchError) -> bool {
    matches!(
        error,
        DatagramDispatchError::Connection(error) if is_benign_connection_error(error)
    )
}

fn is_benign_server_error(error: &ServerError) -> bool {
    match error {
        ServerError::Connection(error) => is_benign_connection_error(error),
        ServerError::OpenChannel(error) => is_benign_open_channel_error(error),
        ServerError::AcceptChannel(error) => is_benign_accept_channel_error(error),
        ServerError::RouteAcceptedChannel(error) => is_benign_route_error(error),
        ServerError::DatagramDispatch(error) => is_benign_datagram_error(error),
        ServerError::Conversation(error) => is_benign_conversation_error(error),
        ServerError::Channel(error) => is_benign_channel_error(error),
        ServerError::Io(error) => is_benign_io_error(error),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use futures_util::future::poll_fn;
    use http::header::HeaderValue;
    use p256::SecretKey as P256SecretKey;
    use rand_core::OsRng;
    use rsa::RsaPrivateKey as JwtRsaPrivateKey;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::traits::PublicKeyParts;
    use sha2::Sha256;
    use signature::{SignatureEncoding, Signer};
    use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, RsaKeypair};
    use ssh3_auth::{build_bearer_token, conversation_id_base64};
    use ssh3_core::{Channel, Conversation};
    use ssh3_h3::{
        ClientControlStream, ClientConversationError, SSH3_USER_HEADER, SSH3_VERSION_STRING,
        SendRequest, build_connect_request, establish_client_conversation,
        generate_conversation_id, new_client,
    };
    use ssh3_proto::{
        ChannelRequest, ChannelRequestMessage, ExecRequest, ExitStatusRequest, Message, PtyRequest,
        SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, SignalRequest, WindowChangeRequest,
    };
    use ssh3_quinn::{client_config_for_certificate, open_channel, self_signed_server_config};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{sleep, timeout};

    use super::{
        BASE64_STANDARD, ServerConfig, current_username, effective_shell, lookup_session_user,
        serve_connection,
    };

    struct TestHarness {
        client_endpoint: quinn::Endpoint,
        client_connection: quinn::Connection,
        conversation: Arc<Conversation>,
        _control_stream: ClientControlStream,
        _send_request: SendRequest,
        driver_task: tokio::task::JoinHandle<()>,
        server_task: tokio::task::JoinHandle<()>,
    }

    struct SessionOutput {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        exit_status: u64,
    }

    impl TestHarness {
        async fn open_session_channel(&self) -> Arc<Channel> {
            open_channel(
                self.conversation.as_ref(),
                &self.client_connection,
                b"session".to_vec(),
                1024,
                10,
            )
            .await
            .unwrap()
        }

        async fn shutdown(self) {
            self.client_connection.close(0u32.into(), b"done");
            let _ = timeout(Duration::from_secs(5), self.driver_task)
                .await
                .unwrap();
            self.client_endpoint.wait_idle().await;
            self.server_task.await.unwrap();
        }
    }

    async fn attempt_harness_with_headers(
        server_config: ServerConfig,
        requested_user: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<TestHarness, ClientConversationError> {
        let (server_config_tls, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config_tls,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            timeout(
                Duration::from_secs(10),
                serve_connection(connection, server_config),
            )
            .await
            .unwrap()
            .unwrap();
        });
        let client_connection = timeout(Duration::from_secs(5), client_connecting)
            .await
            .unwrap()
            .unwrap();

        let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut request = build_connect_request(
            "https://localhost/ssh3-term".parse().unwrap(),
            SSH3_VERSION_STRING,
        )
        .unwrap();
        if let Some(requested_user) = requested_user {
            request.headers_mut().insert(
                SSH3_USER_HEADER,
                HeaderValue::from_str(requested_user).unwrap(),
            );
        }
        if let Some(authorization) = authorization {
            request.headers_mut().insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(authorization).unwrap(),
            );
        }
        let established = timeout(
            Duration::from_secs(5),
            establish_client_conversation(
                &mut send_request,
                client_connection.clone(),
                request,
                30_000,
                10,
            ),
        )
        .await
        .unwrap();
        let established = match established {
            Ok(established) => established,
            Err(err) => {
                client_connection.close(0u32.into(), b"done");
                let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
                client_endpoint.wait_idle().await;
                server_task.await.unwrap();
                return Err(err);
            }
        };

        Ok(TestHarness {
            client_endpoint,
            client_connection,
            conversation: established.conversation,
            _control_stream: established.control_stream,
            _send_request: send_request,
            driver_task,
            server_task,
        })
    }

    async fn attempt_oidc_harness(
        server_config: ServerConfig,
        requested_user: Option<&str>,
        fixture: &OidcFixture,
    ) -> Result<TestHarness, ClientConversationError> {
        let (server_config_tls, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config_tls,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            timeout(
                Duration::from_secs(10),
                serve_connection(connection, server_config),
            )
            .await
            .unwrap()
            .unwrap();
        });
        let client_connection = timeout(Duration::from_secs(5), client_connecting)
            .await
            .unwrap()
            .unwrap();

        let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let conversation_id = generate_conversation_id(&client_connection).unwrap();
        let mut request = build_connect_request(
            "https://localhost/ssh3-term".parse().unwrap(),
            SSH3_VERSION_STRING,
        )
        .unwrap();
        if let Some(requested_user) = requested_user {
            request.headers_mut().insert(
                SSH3_USER_HEADER,
                HeaderValue::from_str(requested_user).unwrap(),
            );
        }
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&fixture.authorization_for_conversation(&conversation_id))
                .unwrap(),
        );
        let established = timeout(
            Duration::from_secs(5),
            establish_client_conversation(
                &mut send_request,
                client_connection.clone(),
                request,
                30_000,
                10,
            ),
        )
        .await
        .unwrap()?;

        driver_task.abort();
        Ok(TestHarness {
            client_endpoint,
            client_connection,
            conversation: established.conversation,
            _control_stream: established.control_stream,
            _send_request: send_request,
            driver_task,
            server_task,
        })
    }

    async fn attempt_harness(
        server_config: ServerConfig,
        requested_user: Option<&str>,
    ) -> Result<TestHarness, ClientConversationError> {
        attempt_harness_with_headers(server_config, requested_user, None).await
    }

    async fn attempt_authenticated_harness(
        server_config: ServerConfig,
        requested_user: &str,
        private_key: &ssh_key::PrivateKey,
        username: &str,
    ) -> Result<TestHarness, ClientConversationError> {
        let (server_config_tls, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config_tls,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            timeout(
                Duration::from_secs(10),
                serve_connection(connection, server_config),
            )
            .await
            .unwrap()
            .unwrap();
        });
        let client_connection = timeout(Duration::from_secs(5), client_connecting)
            .await
            .unwrap()
            .unwrap();

        let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let conversation_id = generate_conversation_id(&client_connection).unwrap();
        let mut request = build_connect_request(
            "https://localhost/ssh3-term".parse().unwrap(),
            SSH3_VERSION_STRING,
        )
        .unwrap();
        request.headers_mut().insert(
            SSH3_USER_HEADER,
            HeaderValue::from_str(requested_user).unwrap(),
        );
        let token = build_bearer_token(private_key, username, &conversation_id).unwrap();
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let established = timeout(
            Duration::from_secs(5),
            establish_client_conversation(
                &mut send_request,
                client_connection.clone(),
                request,
                30_000,
                10,
            ),
        )
        .await
        .unwrap();
        let established = match established {
            Ok(established) => established,
            Err(err) => {
                client_connection.close(0u32.into(), b"done");
                let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
                client_endpoint.wait_idle().await;
                server_task.await.unwrap();
                return Err(err);
            }
        };

        Ok(TestHarness {
            client_endpoint,
            client_connection,
            conversation: established.conversation,
            _control_stream: established.control_stream,
            _send_request: send_request,
            driver_task,
            server_task,
        })
    }

    async fn setup_harness(server_config: ServerConfig) -> TestHarness {
        attempt_harness(server_config, None).await.unwrap()
    }

    async fn collect_session_output(channel: Arc<Channel>) -> SessionOutput {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let message = timeout(Duration::from_secs(5), channel.next_message())
                .await
                .unwrap()
                .unwrap();
            match message {
                Message::Data(data) => match data.data_type {
                    SSH_EXTENDED_DATA_NONE => stdout.extend_from_slice(&data.data),
                    SSH_EXTENDED_DATA_STDERR => stderr.extend_from_slice(&data.data),
                    _ => {}
                },
                Message::ChannelRequest(message) => match message.request {
                    ChannelRequest::ExitStatus(ExitStatusRequest { exit_status }) => {
                        return SessionOutput {
                            stdout,
                            stderr,
                            exit_status,
                        };
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    fn normalize_pty_output(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).replace("\r\n", "\n")
    }

    fn basic_authorization(username: &str, password: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{username}:{password}"))
        )
    }

    struct AuthFixture {
        _tempdir: TempDir,
        authorized_identities_path: PathBuf,
        private_key: ssh_key::PrivateKey,
        username: String,
    }

    #[derive(Clone, Copy)]
    enum AuthKeyAlgorithm {
        Ed25519,
        NistP256,
        Rsa,
    }

    fn auth_private_key(algorithm: AuthKeyAlgorithm) -> ssh_key::PrivateKey {
        match algorithm {
            AuthKeyAlgorithm::Ed25519 => {
                ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[21; 32]))
            }
            AuthKeyAlgorithm::NistP256 => {
                let secret_key = P256SecretKey::from_slice(&[23; 32]).unwrap();
                ssh_key::PrivateKey::from(EcdsaKeypair::NistP256 {
                    public: secret_key.public_key().into(),
                    private: secret_key.into(),
                })
            }
            AuthKeyAlgorithm::Rsa => {
                let rsa_private_key = JwtRsaPrivateKey::new(&mut OsRng, 2048).unwrap();
                ssh_key::PrivateKey::from(RsaKeypair::try_from(&rsa_private_key).unwrap())
            }
        }
    }

    fn create_auth_fixture(algorithm: AuthKeyAlgorithm) -> AuthFixture {
        let tempdir = TempDir::new().unwrap();
        let authorized_identities_path = tempdir.path().join("authorized_keys");
        let private_key = auth_private_key(algorithm);
        fs::write(
            &authorized_identities_path,
            format!("{}\n", private_key.public_key().to_openssh().unwrap()),
        )
        .unwrap();

        AuthFixture {
            _tempdir: tempdir,
            authorized_identities_path,
            private_key,
            username: current_username().unwrap(),
        }
    }

    struct OidcFixture {
        _tempdir: TempDir,
        authorized_identities_path: PathBuf,
        issuer_url: String,
        client_id: String,
        email: String,
        signing_key: JwtRsaPrivateKey,
        username: String,
        provider_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for OidcFixture {
        fn drop(&mut self) {
            self.provider_task.abort();
        }
    }

    impl OidcFixture {
        fn authorization_for_conversation(&self, conversation_id: &[u8; 32]) -> String {
            build_oidc_token(
                &self.issuer_url,
                &self.client_id,
                &self.email,
                Some(&conversation_id_base64(conversation_id)),
                &self.signing_key,
            )
        }
    }

    async fn read_http_request_path(
        stream: &mut tokio::net::TcpStream,
    ) -> Result<String, std::io::Error> {
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        Ok(String::from_utf8_lossy(&buffer)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string())
    }

    fn build_oidc_token(
        issuer_url: &str,
        client_id: &str,
        email: &str,
        nonce: Option<&str>,
        private_key: &JwtRsaPrivateKey,
    ) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key","typ":"JWT"}"#);
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;
        let nonce_claim = nonce
            .map(|nonce| format!(r#","nonce":"{nonce}""#))
            .unwrap_or_default();
        let claims = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"iss":"{issuer_url}","aud":"{client_id}","exp":{exp},"email":"{email}","email_verified":true{nonce_claim}}}"#
            )
            .as_bytes(),
        );
        let signing_input = format!("{header}.{claims}");
        let signing_key = RsaSigningKey::<Sha256>::new(private_key.clone());
        let signature: RsaSignature =
            Signer::try_sign(&signing_key, signing_input.as_bytes()).unwrap();
        format!(
            "Bearer {signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_vec())
        )
    }

    async fn create_oidc_fixture() -> OidcFixture {
        let tempdir = TempDir::new().unwrap();
        let authorized_identities_path = tempdir.path().join("authorized_identities");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let issuer_url = format!("http://{}", listener.local_addr().unwrap());
        let client_id = "ssh3-client-id";
        let email = "alice@example.com";
        let signing_key = JwtRsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = signing_key.to_public_key();
        let discovery_body =
            format!(r#"{{"issuer":"{issuer_url}","jwks_uri":"{issuer_url}/keys"}}"#);
        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-key","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        );
        let provider_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let discovery_body = discovery_body.clone();
                let jwks_body = jwks_body.clone();
                tokio::spawn(async move {
                    let path = read_http_request_path(&mut stream).await.unwrap();
                    let (status_line, body) = match path.as_str() {
                        "/.well-known/openid-configuration" => ("HTTP/1.1 200 OK", discovery_body),
                        "/keys" => ("HTTP/1.1 200 OK", jwks_body),
                        _ => ("HTTP/1.1 404 Not Found", "{}".to_string()),
                    };
                    let response = format!(
                        "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        fs::write(
            &authorized_identities_path,
            format!("oidc {client_id} {issuer_url} {email}\n"),
        )
        .unwrap();

        OidcFixture {
            _tempdir: tempdir,
            authorized_identities_path,
            issuer_url: issuer_url.clone(),
            client_id: client_id.to_string(),
            email: email.to_string(),
            signing_key,
            username: current_username().unwrap(),
            provider_task,
        }
    }

    #[tokio::test]
    async fn exec_requests_run_commands_and_report_exit_status() {
        let harness = setup_harness(ServerConfig::default()).await;
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf 'hello from rust\\n'".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert_eq!(output.stdout, b"hello from rust\n".to_vec());
        assert!(output.stderr.is_empty());
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn pty_requests_create_a_tty_and_apply_live_window_changes() {
        let harness = setup_harness(ServerConfig::default()).await;
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Pty(PtyRequest {
                    term: b"vt100".to_vec(),
                    char_width: 40,
                    char_height: 12,
                    pixel_width: 0,
                    pixel_height: 0,
                    encoded_terminal_modes: Vec::new(),
                }),
            })
            .await
            .unwrap();
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"sleep 0.2; if [ -t 0 ]; then printf 'pty:%s ' \"$TERM\"; stty size; else printf 'notty\\n'; fi".to_vec(),
                }),
            })
            .await
            .unwrap();

        sleep(Duration::from_millis(50)).await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: false,
                request: ChannelRequest::WindowChange(WindowChangeRequest {
                    char_width: 61,
                    char_height: 19,
                    pixel_width: 0,
                    pixel_height: 0,
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        let stdout = normalize_pty_output(&output.stdout);
        assert!(stdout.starts_with("pty:vt100 "));
        assert!(
            stdout.contains("19 61"),
            "unexpected PTY output: {stdout:?}"
        );
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn signal_requests_are_forwarded_to_the_running_session() {
        let harness = setup_harness(ServerConfig::default()).await;
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"trap 'printf trapped\\n; exit 0' TERM; while :; do sleep 1; done"
                        .to_vec(),
                }),
            })
            .await
            .unwrap();

        sleep(Duration::from_millis(100)).await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: false,
                request: ChannelRequest::Signal(SignalRequest {
                    signal_name_without_sig: b"TERM".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert!(String::from_utf8_lossy(&output.stdout).contains("trapped"));
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn requested_user_header_selects_the_session_environment() {
        let username = current_username().expect("current user should resolve");
        let session_user = lookup_session_user(&username).unwrap();
        let mut config = ServerConfig::default();
        config.default_user = Some("does-not-exist".to_string());
        let expected_shell = effective_shell(&config, &session_user);

        let harness = attempt_harness(config.clone(), Some(&username))
            .await
            .unwrap();
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf '%s|%s|%s\\n' \"$HOME\" \"$USER\" \"$SHELL\"".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.trim_end(),
            format!(
                "{}|{}|{}",
                session_user.home_dir.display(),
                username,
                expected_shell.display()
            )
        );
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn bearer_tokens_authorize_session_startup() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let mut config = ServerConfig::default();
        config.require_authentication = true;
        config.authorized_identity_paths = vec![fixture.authorized_identities_path.clone()];
        config.default_user = Some("does-not-exist".to_string());

        let harness = attempt_authenticated_harness(
            config,
            &fixture.username,
            &fixture.private_key,
            &fixture.username,
        )
        .await
        .unwrap();
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf 'authenticated\\n'".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert_eq!(output.stdout, b"authenticated\n".to_vec());
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn missing_bearer_token_is_rejected_when_auth_is_required() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let mut config = ServerConfig::default();
        config.require_authentication = true;
        config.authorized_identity_paths = vec![fixture.authorized_identities_path.clone()];
        config.default_user = Some("does-not-exist".to_string());

        match attempt_harness(config, Some(&fixture.username)).await {
            Err(ClientConversationError::UnexpectedStatus { status }) => {
                assert_eq!(status, http::StatusCode::UNAUTHORIZED);
            }
            Err(ClientConversationError::Stream(err)) if err.is_h3_no_error() => {}
            Err(other) => panic!("expected auth rejection, got {other:?}"),
            Ok(_) => panic!("expected auth rejection"),
        }
    }

    #[tokio::test]
    async fn oidc_identity_tokens_authorize_session_startup() {
        let fixture = create_oidc_fixture().await;
        let mut config = ServerConfig::default();
        config.require_authentication = true;
        config.authorized_identity_paths = vec![fixture.authorized_identities_path.clone()];
        config.default_user = Some("does-not-exist".to_string());

        let harness = attempt_oidc_harness(config, Some(&fixture.username), &fixture)
            .await
            .unwrap();
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf 'authenticated via oidc\\n'".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert_eq!(output.stdout, b"authenticated via oidc\n".to_vec());
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn basic_password_auth_authorizes_session_startup() {
        let username = current_username().unwrap();
        let password = "correct horse battery staple";
        let mut config = ServerConfig::default();
        config.enable_password_login = true;
        config.default_user = Some("does-not-exist".to_string());
        config.password_verifier = Some(Arc::new({
            let username = username.clone();
            move |candidate_username, candidate_password| {
                Ok(candidate_username == username && candidate_password == password)
            }
        }));

        let harness = attempt_harness_with_headers(
            config,
            None,
            Some(&basic_authorization(&username, password)),
        )
        .await
        .unwrap();
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf 'authenticated via password\\n'".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert_eq!(output.stdout, b"authenticated via password\n".to_vec());
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn missing_basic_auth_is_rejected_when_password_login_is_required() {
        let mut config = ServerConfig::default();
        config.enable_password_login = true;
        config.default_user = Some(current_username().unwrap());
        config.password_verifier = Some(Arc::new(|_, _| Ok(false)));

        match attempt_harness(config, None).await {
            Err(ClientConversationError::UnexpectedStatus { status }) => {
                assert_eq!(status, http::StatusCode::UNAUTHORIZED);
            }
            Err(ClientConversationError::Stream(err)) if err.is_h3_no_error() => {}
            Err(other) => panic!("expected auth rejection, got {other:?}"),
            Ok(_) => panic!("expected auth rejection"),
        }
    }

    #[tokio::test]
    async fn nist_p256_bearer_tokens_authorize_session_startup() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::NistP256);
        let mut config = ServerConfig::default();
        config.require_authentication = true;
        config.authorized_identity_paths = vec![fixture.authorized_identities_path.clone()];
        config.default_user = Some("does-not-exist".to_string());

        let harness = attempt_authenticated_harness(
            config,
            &fixture.username,
            &fixture.private_key,
            &fixture.username,
        )
        .await
        .unwrap();
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf 'authenticated via p256\\n'".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert_eq!(output.stdout, b"authenticated via p256\n".to_vec());
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn rsa_bearer_tokens_authorize_session_startup() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Rsa);
        let mut config = ServerConfig::default();
        config.require_authentication = true;
        config.authorized_identity_paths = vec![fixture.authorized_identities_path.clone()];
        config.default_user = Some("does-not-exist".to_string());

        let harness = attempt_authenticated_harness(
            config,
            &fixture.username,
            &fixture.private_key,
            &fixture.username,
        )
        .await
        .unwrap();
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Exec(ExecRequest {
                    command: b"printf 'authenticated via rsa\\n'".to_vec(),
                }),
            })
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        assert_eq!(output.stdout, b"authenticated via rsa\n".to_vec());
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn shell_requests_start_a_login_shell() {
        let harness = setup_harness(ServerConfig::default()).await;
        let channel = harness.open_session_channel().await;
        channel
            .send_request(ChannelRequestMessage {
                want_reply: true,
                request: ChannelRequest::Shell,
            })
            .await
            .unwrap();
        channel
            .write_data(b"printf '%s\\n' \"$0\"\nexit\n", SSH_EXTENDED_DATA_NONE)
            .await
            .unwrap();

        let output = collect_session_output(channel).await;
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.lines().any(|line| line.starts_with('-')),
            "expected a login shell argv[0], got {stdout:?}"
        );
        assert_eq!(output.exit_status, 0);

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn missing_requested_and_default_user_is_rejected() {
        let mut config = ServerConfig::default();
        config.default_user = None;

        let (server_config_tls, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config_tls,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        client_endpoint
            .set_default_client_config(client_config_for_certificate(server_certificate).unwrap());

        let client_connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let client_connection = timeout(Duration::from_secs(5), client_connecting)
            .await
            .unwrap()
            .unwrap();
        let (mut driver, mut send_request) = new_client(client_connection.clone()).await.unwrap();
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = build_connect_request(
            "https://localhost/ssh3-term".parse().unwrap(),
            SSH3_VERSION_STRING,
        )
        .unwrap();
        let mut stream = send_request.send_request(request).await.unwrap();
        match timeout(Duration::from_secs(5), stream.recv_response())
            .await
            .unwrap()
        {
            Ok(response) => assert_eq!(response.status(), http::StatusCode::UNAUTHORIZED),
            Err(err) if err.is_h3_no_error() => {}
            Err(other) => panic!("expected unauthorized response or clean close, got {other:?}"),
        }

        client_connection.close(0u32.into(), b"done");
        let _ = timeout(Duration::from_secs(5), driver_task).await.unwrap();
        client_endpoint.wait_idle().await;
        server_task.await.unwrap();
    }
}
