use std::env;
use std::fmt;
use std::future::poll_fn;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use http::{Uri, header::HeaderValue};
#[cfg(unix)]
use nix::sys::termios::{self, SetArg};
use quinn::{ConnectError, Connection, ConnectionError, Endpoint};
use rand::{RngCore, rngs::OsRng};
use reqwest::StatusCode as HttpStatusCode;
use rustls::{RootCertStore, pki_types::CertificateDer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ssh3_auth::{
    AuthError, bearer_authorization_value, build_bearer_token, conversation_id_base64,
    load_private_key,
};
use ssh3_core::{Channel, ChannelError, Conversation};
use ssh3_h3::{
    BuildConnectRequestError, ClientControlStream, ClientConversationError, ConversationIdError,
    EstablishedClientConversation, SSH3_USER_HEADER, SSH3_VERSION_STRING, SendRequest,
    generate_conversation_id, new_client, response_server_header,
};
use ssh3_proto::{
    ChannelRequest, ChannelRequestMessage, ExecRequest, ExitSignalRequest, Message, PtyRequest,
    SSH_EXTENDED_DATA_NONE, SSH_EXTENDED_DATA_STDERR, SignalRequest, WindowChangeRequest,
};
use ssh3_quinn::{
    AcceptChannelError, ConfigError as QuinnConfigError, IncomingChannelRouter, OpenChannelError,
    RouteAcceptedChannelError, client_config_insecure, client_config_with_roots,
    client_config_with_webpki_roots, open_channel,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use url::Url;

mod agent;

pub use agent::AgentSelection;
use agent::{build_agent_bearer_token, resolve_agent_socket_path};

const DEFAULT_USER_AGENT: &str = SSH3_VERSION_STRING;
const DEFAULT_OIDC_SCOPE: &str = "openid email";
const OIDC_CALLBACK_PATH: &str = "/ssh";

#[derive(Clone, Debug)]
pub enum TrustStrategy {
    WebPkiRoots,
    Certificates(Vec<CertificateDer<'static>>),
    Insecure,
}

#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub use_pkce: bool,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub target_url: Uri,
    pub server_name: Option<String>,
    pub username: Option<String>,
    pub identity_file: Option<PathBuf>,
    pub agent: Option<AgentSelection>,
    pub agent_socket: Option<PathBuf>,
    pub forward_agent: bool,
    pub password: Option<String>,
    pub bearer_token: Option<String>,
    pub oidc: Option<OidcConfig>,
    pub user_agent: String,
    pub max_packet_size: u64,
    pub default_datagrams_queue_size: usize,
    pub trust: TrustStrategy,
}

impl ClientConfig {
    pub fn new(target_url: Uri) -> Self {
        Self {
            target_url,
            server_name: None,
            username: None,
            identity_file: None,
            agent: None,
            agent_socket: None,
            forward_agent: false,
            password: None,
            bearer_token: None,
            oidc: None,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            max_packet_size: 30_000,
            default_datagrams_queue_size: 10,
            trust: TrustStrategy::WebPkiRoots,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SessionRequest {
    Shell,
    Exec(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalSize {
    char_width: u16,
    char_height: u16,
    pixel_width: u16,
    pixel_height: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalTerminalInfo {
    term: Option<String>,
    size: TerminalSize,
}

struct LocalTerminal {
    info: LocalTerminalInfo,
    #[cfg(unix)]
    fd: RawFd,
}

#[cfg(unix)]
struct RawModeGuard {
    fd: RawFd,
    original: termios::Termios,
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let fd = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = termios::tcsetattr(fd, SetArg::TCSANOW, &self.original);
    }
}

#[derive(Default)]
struct SessionRuntime {
    background_tasks: Vec<tokio::task::JoinHandle<()>>,
    #[cfg(unix)]
    raw_mode_guard: Option<RawModeGuard>,
}

impl Drop for SessionRuntime {
    fn drop(&mut self) {
        for task in &self.background_tasks {
            task.abort();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedSession {
    pub server_header: Option<String>,
    pub exit_status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub enum OidcError {
    Io(io::Error),
    Reqwest(reqwest::Error),
    Url(url::ParseError),
    InvalidResponse(&'static str),
    ProviderError(String),
}

impl fmt::Display for OidcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Reqwest(err) => write!(f, "{err}"),
            Self::Url(err) => write!(f, "{err}"),
            Self::InvalidResponse(message) => write!(f, "{message}"),
            Self::ProviderError(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for OidcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Reqwest(err) => Some(err),
            Self::Url(err) => Some(err),
            Self::InvalidResponse(_) => None,
            Self::ProviderError(_) => None,
        }
    }
}

impl From<io::Error> for OidcError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<reqwest::Error> for OidcError {
    fn from(value: reqwest::Error) -> Self {
        Self::Reqwest(value)
    }
}

impl From<url::ParseError> for OidcError {
    fn from(value: url::ParseError) -> Self {
        Self::Url(value)
    }
}

#[derive(Debug)]
pub enum ClientError {
    MissingHost,
    Resolve(io::Error),
    Endpoint(io::Error),
    Connect(ConnectError),
    Connection(ConnectionError),
    QuinnConfig(QuinnConfigError),
    H3Connection(h3::error::ConnectionError),
    ConversationId(ConversationIdError),
    BuildRequest(BuildConnectRequestError),
    ClientConversation(ClientConversationError),
    OpenChannel(OpenChannelError),
    Channel(ChannelError),
    Io(io::Error),
    InvalidCertificateBundle,
    InvalidHeaderValue(http::header::InvalidHeaderValue),
    SshKey(ssh_key::Error),
    Auth(AuthError),
    Oidc(OidcError),
    MissingUsernameForIdentity,
    MissingUsernameForAgent,
    MissingUsernameForPassword,
    AgentUnavailable,
    AgentKeyNotFound,
    UnsupportedAgentKey(String),
    ConflictingAuthenticationMethods,
    ExitSignal(ExitSignalRequest),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHost => write!(f, "target URL is missing a host"),
            Self::Resolve(err) => write!(f, "{err}"),
            Self::Endpoint(err) => write!(f, "{err}"),
            Self::Connect(err) => write!(f, "{err}"),
            Self::Connection(err) => write!(f, "{err}"),
            Self::QuinnConfig(err) => write!(f, "{err}"),
            Self::H3Connection(err) => write!(f, "{err}"),
            Self::ConversationId(err) => write!(f, "{err}"),
            Self::BuildRequest(err) => write!(f, "{err}"),
            Self::ClientConversation(err) => write!(f, "{err}"),
            Self::OpenChannel(err) => write!(f, "{err}"),
            Self::Channel(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::InvalidCertificateBundle => write!(
                f,
                "certificate bundle did not contain any valid certificates"
            ),
            Self::InvalidHeaderValue(err) => write!(f, "{err}"),
            Self::SshKey(err) => write!(f, "{err}"),
            Self::Auth(err) => write!(f, "{err}"),
            Self::Oidc(err) => write!(f, "{err}"),
            Self::MissingUsernameForIdentity => {
                write!(f, "an identity file requires an explicit username")
            }
            Self::MissingUsernameForAgent => {
                write!(f, "SSH agent authentication requires an explicit username")
            }
            Self::MissingUsernameForPassword => {
                write!(f, "password authentication requires an explicit username")
            }
            Self::AgentUnavailable => write!(f, "no SSH agent is available"),
            Self::AgentKeyNotFound => write!(f, "no matching SSH agent key was found"),
            Self::UnsupportedAgentKey(algorithm) => {
                write!(f, "unsupported SSH agent key algorithm: {algorithm}")
            }
            Self::ConflictingAuthenticationMethods => write!(
                f,
                "configure only one of: identity file, SSH agent, password, raw bearer token, or OIDC"
            ),
            Self::ExitSignal(signal) => write!(
                f,
                "remote process exited with signal {}: {}",
                String::from_utf8_lossy(&signal.signal_name_without_sig),
                String::from_utf8_lossy(&signal.error_message_utf8)
            ),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingHost => None,
            Self::Resolve(err) => Some(err),
            Self::Endpoint(err) => Some(err),
            Self::Connect(err) => Some(err),
            Self::Connection(err) => Some(err),
            Self::QuinnConfig(err) => Some(err),
            Self::H3Connection(err) => Some(err),
            Self::ConversationId(err) => Some(err),
            Self::BuildRequest(err) => Some(err),
            Self::ClientConversation(err) => Some(err),
            Self::OpenChannel(err) => Some(err),
            Self::Channel(err) => Some(err),
            Self::Io(err) => Some(err),
            Self::InvalidCertificateBundle => None,
            Self::InvalidHeaderValue(err) => Some(err),
            Self::SshKey(err) => Some(err),
            Self::Auth(err) => Some(err),
            Self::Oidc(err) => Some(err),
            Self::MissingUsernameForIdentity => None,
            Self::MissingUsernameForAgent => None,
            Self::MissingUsernameForPassword => None,
            Self::AgentUnavailable => None,
            Self::AgentKeyNotFound => None,
            Self::UnsupportedAgentKey(_) => None,
            Self::ConflictingAuthenticationMethods => None,
            Self::ExitSignal(_) => None,
        }
    }
}

impl From<QuinnConfigError> for ClientError {
    fn from(value: QuinnConfigError) -> Self {
        Self::QuinnConfig(value)
    }
}

impl From<h3::error::ConnectionError> for ClientError {
    fn from(value: h3::error::ConnectionError) -> Self {
        Self::H3Connection(value)
    }
}

impl From<ConversationIdError> for ClientError {
    fn from(value: ConversationIdError) -> Self {
        Self::ConversationId(value)
    }
}

impl From<BuildConnectRequestError> for ClientError {
    fn from(value: BuildConnectRequestError) -> Self {
        Self::BuildRequest(value)
    }
}

impl From<AuthError> for ClientError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value)
    }
}

impl From<ssh_key::Error> for ClientError {
    fn from(value: ssh_key::Error) -> Self {
        Self::SshKey(value)
    }
}

impl From<OidcError> for ClientError {
    fn from(value: OidcError) -> Self {
        Self::Oidc(value)
    }
}

impl From<ClientConversationError> for ClientError {
    fn from(value: ClientConversationError) -> Self {
        Self::ClientConversation(value)
    }
}

impl From<OpenChannelError> for ClientError {
    fn from(value: OpenChannelError) -> Self {
        Self::OpenChannel(value)
    }
}

impl From<ChannelError> for ClientError {
    fn from(value: ChannelError) -> Self {
        Self::Channel(value)
    }
}

impl From<io::Error> for ClientError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<http::header::InvalidHeaderValue> for ClientError {
    fn from(value: http::header::InvalidHeaderValue) -> Self {
        Self::InvalidHeaderValue(value)
    }
}

struct ResolvedTarget {
    remote_addr: SocketAddr,
    server_name: String,
}

struct ActiveClient {
    endpoint: Endpoint,
    connection: Connection,
    conversation: Arc<Conversation>,
    _control_stream: ClientControlStream,
    _send_request: SendRequest,
    driver_task: tokio::task::JoinHandle<()>,
    incoming_channels_task: tokio::task::JoinHandle<()>,
    incoming_datagrams_task: tokio::task::JoinHandle<()>,
    server_header: Option<String>,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
}

impl ActiveClient {
    async fn shutdown(self) {
        self.connection.close(0u32.into(), b"done");
        let _ = self.driver_task.await;
        let _ = self.incoming_channels_task.await;
        let _ = self.incoming_datagrams_task.await;
        self.endpoint.wait_idle().await;
    }

    async fn open_session_channel(&self) -> Result<Arc<Channel>, ClientError> {
        open_channel(
            self.conversation.as_ref(),
            &self.connection,
            b"session".to_vec(),
            self.max_packet_size,
            self.default_datagrams_queue_size,
        )
        .await
        .map_err(ClientError::from)
    }
}

pub fn load_certificates(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateDer<'static>>, ClientError> {
    let bytes = std::fs::read(path).map_err(ClientError::Io)?;
    if bytes.starts_with(b"-----BEGIN") {
        let mut reader = BufReader::new(bytes.as_slice());
        let certificates = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ClientError::Io)?;
        if certificates.is_empty() {
            return Err(ClientError::InvalidCertificateBundle);
        }
        Ok(certificates)
    } else {
        Ok(vec![CertificateDer::from(bytes)])
    }
}

async fn send_initial_session_requests(
    channel: &Channel,
    request: &SessionRequest,
    terminal: Option<&LocalTerminalInfo>,
) -> Result<(), ClientError> {
    if matches!(request, SessionRequest::Shell)
        && let Some(terminal) = terminal
    {
        send_pty_request(channel, terminal).await?;
    }

    let request = match request {
        SessionRequest::Shell => ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Shell,
        },
        SessionRequest::Exec(command) => ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Exec(ExecRequest {
                command: command.as_bytes().to_vec(),
            }),
        },
    };
    channel
        .send_request(request)
        .await
        .map_err(ClientError::from)
}

async fn send_pty_request(
    channel: &Channel,
    terminal: &LocalTerminalInfo,
) -> Result<(), ClientError> {
    channel
        .send_request(ChannelRequestMessage {
            want_reply: true,
            request: ChannelRequest::Pty(PtyRequest {
                term: terminal.term.clone().unwrap_or_default().into_bytes(),
                char_width: terminal.size.char_width.into(),
                char_height: terminal.size.char_height.into(),
                pixel_width: terminal.size.pixel_width.into(),
                pixel_height: terminal.size.pixel_height.into(),
                encoded_terminal_modes: Vec::new(),
            }),
        })
        .await
        .map_err(ClientError::from)
}

async fn send_forward_agent_request(channel: &Channel) -> Result<(), ClientError> {
    channel
        .write_data(b"forward-agent", SSH_EXTENDED_DATA_NONE)
        .await
        .map(|_| ())
        .map_err(ClientError::from)
}

async fn send_window_change_request(
    channel: &Channel,
    size: TerminalSize,
) -> Result<(), ClientError> {
    channel
        .send_request(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::WindowChange(WindowChangeRequest {
                char_width: size.char_width.into(),
                char_height: size.char_height.into(),
                pixel_width: size.pixel_width.into(),
                pixel_height: size.pixel_height.into(),
            }),
        })
        .await
        .map_err(ClientError::from)
}

async fn send_signal_request(channel: &Channel, signal_name: &str) -> Result<(), ClientError> {
    channel
        .send_request(ChannelRequestMessage {
            want_reply: false,
            request: ChannelRequest::Signal(SignalRequest {
                signal_name_without_sig: signal_name.as_bytes().to_vec(),
            }),
        })
        .await
        .map_err(ClientError::from)
}

#[cfg(unix)]
fn detect_local_terminal() -> Result<Option<LocalTerminal>, ClientError> {
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    let is_tty = unsafe { nix::libc::isatty(fd) } == 1;
    if !is_tty {
        return Ok(None);
    }

    Ok(Some(LocalTerminal {
        info: LocalTerminalInfo {
            term: env::var("TERM").ok().filter(|term| !term.is_empty()),
            size: read_terminal_size(fd)?,
        },
        fd,
    }))
}

#[cfg(not(unix))]
fn detect_local_terminal() -> Result<Option<LocalTerminal>, ClientError> {
    Ok(None)
}

#[cfg(unix)]
fn read_terminal_size(fd: RawFd) -> Result<TerminalSize, ClientError> {
    let mut size = std::mem::MaybeUninit::<nix::libc::winsize>::zeroed();
    let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCGWINSZ, size.as_mut_ptr()) };
    if result == -1 {
        return Err(ClientError::Io(io::Error::last_os_error()));
    }

    let size = unsafe { size.assume_init() };
    Ok(TerminalSize {
        char_width: size.ws_col,
        char_height: size.ws_row,
        pixel_width: size.ws_xpixel,
        pixel_height: size.ws_ypixel,
    })
}

#[cfg(unix)]
fn enable_raw_mode(fd: RawFd) -> Result<RawModeGuard, ClientError> {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut termios_state = termios::tcgetattr(fd).map_err(io::Error::from)?;
    let original = termios_state.clone();
    termios::cfmakeraw(&mut termios_state);
    termios::tcsetattr(fd, SetArg::TCSANOW, &termios_state).map_err(io::Error::from)?;
    Ok(RawModeGuard {
        fd: fd.as_raw_fd(),
        original,
    })
}

#[cfg(unix)]
fn spawn_resize_forwarder(channel: Arc<Channel>, fd: RawFd) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut winsize_signal = match signal(SignalKind::window_change()) {
            Ok(signal) => signal,
            Err(_) => return,
        };

        while winsize_signal.recv().await.is_some() {
            let size = match read_terminal_size(fd) {
                Ok(size) => size,
                Err(_) => return,
            };
            if send_window_change_request(channel.as_ref(), size)
                .await
                .is_err()
            {
                return;
            }
        }
    })
}

#[cfg(unix)]
fn spawn_signal_forwarders(channel: Arc<Channel>) -> Vec<tokio::task::JoinHandle<()>> {
    [
        ("INT", SignalKind::interrupt()),
        ("TERM", SignalKind::terminate()),
        ("QUIT", SignalKind::quit()),
        ("HUP", SignalKind::hangup()),
    ]
    .into_iter()
    .filter_map(|(signal_name, kind)| {
        let mut signal = signal(kind).ok()?;
        let channel = channel.clone();
        Some(tokio::spawn(async move {
            while signal.recv().await.is_some() {
                if send_signal_request(channel.as_ref(), signal_name)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }))
    })
    .collect()
}

#[cfg(not(unix))]
fn spawn_signal_forwarders(_channel: Arc<Channel>) -> Vec<tokio::task::JoinHandle<()>> {
    Vec::new()
}

fn build_session_runtime(
    client: &ActiveClient,
    config: &ClientConfig,
    channel: Arc<Channel>,
    request: &SessionRequest,
    terminal: Option<&LocalTerminal>,
) -> Result<SessionRuntime, ClientError> {
    let mut runtime = SessionRuntime {
        background_tasks: spawn_signal_forwarders(channel.clone()),
        #[cfg(unix)]
        raw_mode_guard: None,
    };

    #[cfg(unix)]
    if matches!(request, SessionRequest::Shell)
        && let Some(terminal) = terminal
    {
        runtime.raw_mode_guard = Some(enable_raw_mode(terminal.fd)?);
        runtime
            .background_tasks
            .push(spawn_resize_forwarder(channel, terminal.fd));
    }

    if config.forward_agent {
        #[cfg(unix)]
        runtime.background_tasks.push(spawn_agent_forwarder(
            client.conversation.clone(),
            resolve_agent_socket_path(config)?,
        ));

        #[cfg(not(unix))]
        return Err(ClientError::AgentUnavailable);
    }

    Ok(runtime)
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: Option<String>,
}

fn auth_method_count(config: &ClientConfig) -> usize {
    usize::from(config.identity_file.is_some())
        + usize::from(config.agent.is_some())
        + usize::from(config.password.is_some())
        + usize::from(
            config
                .bearer_token
                .as_deref()
                .map(str::trim)
                .is_some_and(|token| !token.is_empty()),
        )
        + usize::from(config.oidc.is_some())
}

fn basic_authorization_value(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("{username}:{password}"))
    )
}

fn default_browser_opener(url: String) -> Result<(), OidcError> {
    if try_open_browser(&url) {
        return Ok(());
    }
    eprintln!("Open this URL in your browser:\n{url}");
    Ok(())
}

fn try_open_browser(url: &str) -> bool {
    #[cfg(target_os = "android")]
    if StdCommand::new("termux-open-url").arg(url).spawn().is_ok() {
        return true;
    }

    #[cfg(target_os = "windows")]
    if StdCommand::new("cmd")
        .args(["/C", "start", "", url])
        .spawn()
        .is_ok()
    {
        return true;
    }

    #[cfg(target_os = "macos")]
    if StdCommand::new("open").arg(url).spawn().is_ok() {
        return true;
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    if StdCommand::new("xdg-open").arg(url).spawn().is_ok() {
        return true;
    }

    false
}

fn random_urlsafe(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn oidc_code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn fetch_oidc_discovery_document(
    issuer_url: &str,
) -> Result<OidcDiscoveryDocument, OidcError> {
    let client = reqwest::Client::new();
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer_url.trim_end_matches('/')
    );
    client
        .get(discovery_url)
        .send()
        .await?
        .error_for_status()?
        .json::<OidcDiscoveryDocument>()
        .await
        .map_err(OidcError::from)
}

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Result<String, OidcError> {
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

    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

async fn wait_for_oidc_callback(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, OidcError> {
    fn callback_response(status_line: &str, body: &str) -> String {
        format!(
            "{status_line}\r\ncontent-type: text/plain; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    loop {
        let (mut stream, _) = listener.accept().await?;
        let request = read_http_request(&mut stream).await?;
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or(OidcError::InvalidResponse(
                "malformed OIDC callback request",
            ))?;
        let callback_url = Url::parse(&format!("http://localhost{target}"))?;
        let mut code = None;
        let mut state = None;
        let mut provider_error = None;
        for (key, value) in callback_url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => provider_error = Some(value.into_owned()),
                _ => {}
            }
        }

        if let Some(provider_error) = provider_error {
            let response =
                callback_response("HTTP/1.1 400 Bad Request", "OIDC authentication failed.\n");
            let _ = stream.write_all(response.as_bytes()).await;
            return Err(OidcError::ProviderError(provider_error));
        }
        if state.as_deref() != Some(expected_state) {
            let response = callback_response("HTTP/1.1 400 Bad Request", "OIDC state mismatch.\n");
            let _ = stream.write_all(response.as_bytes()).await;
            return Err(OidcError::InvalidResponse("OIDC state mismatch"));
        }
        let Some(code) = code else {
            let response =
                callback_response("HTTP/1.1 400 Bad Request", "OIDC callback missing code.\n");
            let _ = stream.write_all(response.as_bytes()).await;
            return Err(OidcError::InvalidResponse("OIDC callback missing code"));
        };

        let response = callback_response("HTTP/1.1 200 OK", "you can now close this tab");
        let _ = stream.write_all(response.as_bytes()).await;
        return Ok(code);
    }
}

async fn exchange_oidc_code(
    token_endpoint: &str,
    oidc: &OidcConfig,
    redirect_uri: &str,
    code: &str,
    code_verifier: Option<&str>,
) -> Result<String, OidcError> {
    let client = reqwest::Client::new();
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("client_id", oidc.client_id.clone()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if let Some(client_secret) = oidc.client_secret.as_deref() {
        form.push(("client_secret", client_secret.to_string()));
    }
    if let Some(code_verifier) = code_verifier {
        form.push(("code_verifier", code_verifier.to_string()));
    }

    let response = client.post(token_endpoint).form(&form).send().await?;
    if response.status() != HttpStatusCode::OK {
        return Err(OidcError::ProviderError(format!(
            "OIDC token endpoint returned {}",
            response.status()
        )));
    }
    let token_response = response.json::<OidcTokenResponse>().await?;
    token_response
        .id_token
        .filter(|token| !token.is_empty())
        .ok_or(OidcError::InvalidResponse(
            "OIDC token response did not include an id_token",
        ))
}

async fn authenticate_oidc_with_browser_opener(
    oidc: &OidcConfig,
    expected_nonce: &str,
    browser_opener: fn(String) -> Result<(), OidcError>,
) -> Result<String, OidcError> {
    let discovery = fetch_oidc_discovery_document(&oidc.issuer_url).await?;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}{OIDC_CALLBACK_PATH}",
        listener.local_addr()?.port()
    );
    let state = random_urlsafe(24);
    let code_verifier = oidc.use_pkce.then(|| random_urlsafe(48));
    let mut auth_url = Url::parse(&discovery.authorization_endpoint)?;
    {
        let mut query = auth_url.query_pairs_mut();
        query.append_pair("response_type", "code");
        query.append_pair("client_id", &oidc.client_id);
        query.append_pair("redirect_uri", &redirect_uri);
        query.append_pair("scope", DEFAULT_OIDC_SCOPE);
        query.append_pair("state", &state);
        query.append_pair("nonce", expected_nonce);
        if let Some(code_verifier) = code_verifier.as_deref() {
            query.append_pair("code_challenge", &oidc_code_challenge(code_verifier));
            query.append_pair("code_challenge_method", "S256");
        }
    }
    browser_opener(auth_url.to_string())?;
    let code = wait_for_oidc_callback(listener, &state).await?;
    exchange_oidc_code(
        &discovery.token_endpoint,
        oidc,
        &redirect_uri,
        &code,
        code_verifier.as_deref(),
    )
    .await
}

async fn precomputed_authorization_header(
    config: &ClientConfig,
) -> Result<Option<String>, ClientError> {
    if auth_method_count(config) > 1 {
        return Err(ClientError::ConflictingAuthenticationMethods);
    }

    if let Some(token) = config
        .bearer_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        return Ok(Some(bearer_authorization_value(token)));
    }

    if let Some(password) = config.password.as_deref() {
        let username = config
            .username
            .as_deref()
            .ok_or(ClientError::MissingUsernameForPassword)?;
        return Ok(Some(basic_authorization_value(username, password)));
    }

    Ok(None)
}

fn activate_client(
    endpoint: Endpoint,
    connection: Connection,
    send_request: SendRequest,
    driver_task: tokio::task::JoinHandle<()>,
    established: EstablishedClientConversation,
    max_packet_size: u64,
    default_datagrams_queue_size: usize,
) -> ActiveClient {
    let channel_router = Arc::new(IncomingChannelRouter::new());
    channel_router.register_conversation(established.conversation.clone());
    let incoming_channels_task = tokio::spawn({
        let channel_router = channel_router.clone();
        let connection = connection.clone();
        async move {
            if let Err(err) = channel_router
                .accept_and_route_channels_forever(connection)
                .await
                && !is_benign_route_error(&err)
            {
                eprintln!("ssh3-client incoming channel error: {err}");
            }
        }
    });
    let incoming_datagrams_task = tokio::spawn({
        let connection = connection.clone();
        let conversation = established.conversation.clone();
        async move {
            if let Err(err) = ssh3_h3::dispatch_datagrams_forever(conversation, connection).await
                && !is_benign_datagram_dispatch_error(&err)
            {
                eprintln!("ssh3-client incoming datagram error: {err}");
            }
        }
    });

    ActiveClient {
        endpoint,
        connection,
        conversation: established.conversation,
        _control_stream: established.control_stream,
        _send_request: send_request,
        driver_task,
        incoming_channels_task,
        incoming_datagrams_task,
        server_header: response_server_header(&established.response).map(str::to_owned),
        max_packet_size,
        default_datagrams_queue_size,
    }
}

pub async fn run_exec_capture(
    config: &ClientConfig,
    command: impl AsRef<str>,
) -> Result<CapturedSession, ClientError> {
    let client = connect_client(config).await?;
    let result = run_capture_on_client(
        &client,
        config,
        SessionRequest::Exec(command.as_ref().to_string()),
    )
    .await;
    client.shutdown().await;
    result
}

#[cfg(test)]
async fn run_exec_capture_with_browser_opener(
    config: &ClientConfig,
    command: impl AsRef<str>,
    browser_opener: fn(String) -> Result<(), OidcError>,
) -> Result<CapturedSession, ClientError> {
    let client = connect_client_with_browser_opener(config, browser_opener).await?;
    let result = run_capture_on_client(
        &client,
        config,
        SessionRequest::Exec(command.as_ref().to_string()),
    )
    .await;
    client.shutdown().await;
    result
}

pub async fn run_session_stdio(
    config: &ClientConfig,
    request: SessionRequest,
) -> Result<i32, ClientError> {
    let client = connect_client(config).await?;
    let result = run_stdio_on_client(&client, config, request).await;
    client.shutdown().await;
    result
}

async fn connect_client(config: &ClientConfig) -> Result<ActiveClient, ClientError> {
    connect_client_with_browser_opener(config, default_browser_opener).await
}

async fn connect_client_with_browser_opener(
    config: &ClientConfig,
    browser_opener: fn(String) -> Result<(), OidcError>,
) -> Result<ActiveClient, ClientError> {
    let precomputed_authorization = precomputed_authorization_header(config).await?;

    let resolved = resolve_target(&config.target_url, config.server_name.as_deref()).await?;
    let bind_addr = client_bind_addr(resolved.remote_addr);
    let mut endpoint = Endpoint::client(bind_addr).map_err(ClientError::Endpoint)?;
    endpoint.set_default_client_config(client_quinn_config(&config.trust)?);

    let connection = endpoint
        .connect(resolved.remote_addr, &resolved.server_name)
        .map_err(ClientError::Connect)?
        .await
        .map_err(ClientError::Connection)?;

    let (mut driver, mut send_request) = new_client(connection.clone()).await?;
    let driver_task = tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let conversation_id = generate_conversation_id(&connection)?;
    let mut request =
        ssh3_h3::build_connect_request(config.target_url.clone(), &config.user_agent)?;
    if let Some(username) = config.username.as_deref() {
        request
            .headers_mut()
            .insert(SSH3_USER_HEADER, HeaderValue::from_str(username)?);
    }
    if let Some(token) = precomputed_authorization.as_deref() {
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, HeaderValue::from_str(token)?);
    } else if let Some(oidc) = config.oidc.as_ref() {
        let token = authenticate_oidc_with_browser_opener(
            oidc,
            &conversation_id_base64(&conversation_id),
            browser_opener,
        )
        .await?;
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&bearer_authorization_value(&token))?,
        );
    } else if let Some(identity_path) = config.identity_file.as_ref() {
        let username = config
            .username
            .as_deref()
            .ok_or(ClientError::MissingUsernameForIdentity)?;
        let private_key = load_private_key(identity_path)?;
        let token = build_bearer_token(&private_key, username, &conversation_id)?;
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&bearer_authorization_value(&token))?,
        );
    } else if let Some(agent_selection) = config.agent.as_ref() {
        let username = config
            .username
            .as_deref()
            .ok_or(ClientError::MissingUsernameForAgent)?;
        let config = config.clone();
        let agent_selection = agent_selection.clone();
        let username = username.to_string();
        let token = tokio::task::spawn_blocking(move || {
            build_agent_bearer_token(&config, &agent_selection, &username, &conversation_id)
        })
        .await
        .map_err(|err| ClientError::Io(io::Error::other(err.to_string())))??;
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&bearer_authorization_value(&token))?,
        );
    }
    let established = ssh3_h3::establish_client_conversation(
        &mut send_request,
        connection.clone(),
        request,
        config.max_packet_size,
        config.default_datagrams_queue_size,
    )
    .await?;
    driver_task.abort();
    Ok(activate_client(
        endpoint,
        connection,
        send_request,
        driver_task,
        established,
        config.max_packet_size,
        config.default_datagrams_queue_size,
    ))
}

fn client_quinn_config(trust: &TrustStrategy) -> Result<quinn::ClientConfig, ClientError> {
    match trust {
        TrustStrategy::WebPkiRoots => client_config_with_webpki_roots().map_err(ClientError::from),
        TrustStrategy::Certificates(certificates) => {
            let mut roots = RootCertStore::empty();
            let (added, _) = roots.add_parsable_certificates(certificates.iter().cloned());
            if added == 0 {
                return Err(ClientError::InvalidCertificateBundle);
            }
            client_config_with_roots(roots).map_err(ClientError::from)
        }
        TrustStrategy::Insecure => client_config_insecure().map_err(ClientError::from),
    }
}

async fn resolve_target(
    uri: &Uri,
    server_name_override: Option<&str>,
) -> Result<ResolvedTarget, ClientError> {
    let host = uri.host().ok_or(ClientError::MissingHost)?;
    let remote_addr = tokio::net::lookup_host((host, uri.port_u16().unwrap_or(443)))
        .await
        .map_err(ClientError::Resolve)?
        .next()
        .ok_or_else(|| {
            ClientError::Resolve(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "target host did not resolve to an address",
            ))
        })?;

    Ok(ResolvedTarget {
        remote_addr,
        server_name: server_name_override.unwrap_or(host).to_string(),
    })
}

fn client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
    match remote_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    }
}

async fn run_capture_on_client(
    client: &ActiveClient,
    config: &ClientConfig,
    request: SessionRequest,
) -> Result<CapturedSession, ClientError> {
    let channel = client.open_session_channel().await?;
    if config.forward_agent {
        send_forward_agent_request(channel.as_ref()).await?;
    }
    let session_runtime = build_session_runtime(client, config, channel.clone(), &request, None)?;
    send_initial_session_requests(channel.as_ref(), &request, None).await?;
    if !config.forward_agent {
        channel.close().await?;
    }

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = loop {
        match channel.next_message().await? {
            Message::Data(data) => match data.data_type {
                SSH_EXTENDED_DATA_NONE => stdout.extend_from_slice(&data.data),
                SSH_EXTENDED_DATA_STDERR => stderr.extend_from_slice(&data.data),
                _ => {}
            },
            Message::ChannelRequest(message) => match message.request {
                ChannelRequest::ExitStatus(status) => {
                    break Ok(CapturedSession {
                        server_header: client.server_header.clone(),
                        exit_status: status.exit_status as i32,
                        stdout,
                        stderr,
                    });
                }
                ChannelRequest::ExitSignal(signal) => break Err(ClientError::ExitSignal(signal)),
                _ => {}
            },
            _ => {}
        }
    };
    drop(session_runtime);
    result
}

async fn run_stdio_on_client(
    client: &ActiveClient,
    config: &ClientConfig,
    request: SessionRequest,
) -> Result<i32, ClientError> {
    let channel = client.open_session_channel().await?;
    let terminal = detect_local_terminal()?;
    if config.forward_agent {
        send_forward_agent_request(channel.as_ref()).await?;
    }
    send_initial_session_requests(
        channel.as_ref(),
        &request,
        terminal.as_ref().map(|terminal| &terminal.info),
    )
    .await?;
    let session_runtime =
        build_session_runtime(client, config, channel.clone(), &request, terminal.as_ref())?;

    let stdin_task = tokio::spawn({
        let channel = channel.clone();
        async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![
                0;
                usize::try_from(channel.max_packet_size())
                    .unwrap_or(30_000)
                    .max(1)
            ];
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                if n == 0 {
                    let _ = channel.close().await;
                    return;
                }
                if channel
                    .write_data(&buf[..n], SSH_EXTENDED_DATA_NONE)
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();

    let result = loop {
        match channel.next_message().await? {
            Message::Data(data) => match data.data_type {
                SSH_EXTENDED_DATA_NONE => {
                    stdout.write_all(&data.data).await?;
                    stdout.flush().await?;
                }
                SSH_EXTENDED_DATA_STDERR => {
                    stderr.write_all(&data.data).await?;
                    stderr.flush().await?;
                }
                _ => {}
            },
            Message::ChannelRequest(message) => match message.request {
                ChannelRequest::ExitStatus(status) => {
                    break Ok(status.exit_status as i32);
                }
                ChannelRequest::ExitSignal(signal) => {
                    break Err(ClientError::ExitSignal(signal));
                }
                _ => {}
            },
            _ => {}
        }
    };

    stdin_task.abort();
    drop(session_runtime);
    result
}

fn is_benign_connection_error(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::ApplicationClosed(_)
            | ConnectionError::ConnectionClosed(_)
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

fn is_benign_open_channel_error(error: &OpenChannelError) -> bool {
    matches!(error, OpenChannelError::Connection(error) if is_benign_connection_error(error))
}

fn is_benign_client_error(error: &ClientError) -> bool {
    match error {
        ClientError::Connection(error) => is_benign_connection_error(error),
        ClientError::OpenChannel(error) => is_benign_open_channel_error(error),
        ClientError::Channel(error) => is_benign_channel_error(error),
        ClientError::Io(error) => is_benign_io_error(error),
        _ => false,
    }
}

fn is_benign_route_error(error: &RouteAcceptedChannelError) -> bool {
    matches!(
        error,
        RouteAcceptedChannelError::Accept(AcceptChannelError::Connection(error))
            if is_benign_connection_error(error)
    )
}

fn is_benign_datagram_dispatch_error(error: &ssh3_h3::DatagramDispatchError) -> bool {
    matches!(
        error,
        ssh3_h3::DatagramDispatchError::Connection(error) if is_benign_connection_error(error)
    )
}

#[cfg(unix)]
fn spawn_agent_forwarder(
    conversation: Arc<Conversation>,
    agent_socket: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let channel = match conversation.accept_channel().await {
                Ok(channel) => channel,
                Err(_) => return,
            };
            if channel.channel_type() != b"agent-connection" {
                let _ = channel.close().await;
                continue;
            }

            if let Err(err) = forward_agent_channel(channel, &agent_socket).await {
                if is_benign_client_error(&err) {
                    continue;
                }
                eprintln!("ssh3-client agent forwarding error: {err}");
                return;
            }
        }
    })
}

#[cfg(unix)]
async fn forward_agent_channel(
    channel: Arc<Channel>,
    agent_socket: &Path,
) -> Result<(), ClientError> {
    let stream = UnixStream::connect(agent_socket).await?;
    let (mut reader, mut writer) = stream.into_split();

    let mut to_agent = tokio::spawn({
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
            Ok::<(), ClientError>(())
        }
    });

    let mut from_agent = tokio::spawn({
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
                    return Ok::<(), ClientError>(());
                }
                channel
                    .write_data(&buf[..n], SSH_EXTENDED_DATA_NONE)
                    .await?;
            }
        }
    });

    tokio::select! {
        result = &mut to_agent => {
            from_agent.abort();
            let _ = channel.close().await;
            result.map_err(|err| ClientError::Io(io::Error::other(err.to_string())))?
        }
        result = &mut from_agent => {
            to_agent.abort();
            let _ = channel.close().await;
            result.map_err(|err| ClientError::Io(io::Error::other(err.to_string())))?
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::fs::File as StdFile;
    use std::future::poll_fn;
    use std::io;
    #[cfg(unix)]
    use std::io::{Read, Write};
    #[cfg(unix)]
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::process::{Command as StdCommand, Stdio};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use http::{StatusCode, header::HeaderValue};
    #[cfg(unix)]
    use nix::pty::{Winsize, openpty};
    #[cfg(unix)]
    use nix::unistd::{Uid, User};
    use p256::SecretKey as P256SecretKey;
    use quinn::Endpoint;
    use rand_core::OsRng;
    use rsa::BigUint as RsaBigUint;
    use rsa::RsaPrivateKey as JwtRsaPrivateKey;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
    use rsa::traits::PublicKeyParts;
    use sha2::Sha256;
    use signature::{SignatureEncoding, Signer};
    use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
    use ssh_key::{Algorithm, HashAlg, Signature};
    use ssh3_auth::bearer_authorization_value;
    use ssh3_core::Channel;
    use ssh3_h3::{
        SSH3_USER_HEADER, SSH3_VERSION_STRING, accept_server_conversation, build_connect_request,
        establish_client_conversation, generate_conversation_id, is_ssh3_connect, new_client,
        new_server, response_with_server_header,
    };
    use ssh3_proto::{ChannelRequest, Message, SSH_EXTENDED_DATA_NONE};
    use ssh3_quinn::{
        accept_bi_channel, open_tcp_forwarding_channel, open_udp_forwarding_channel,
        self_signed_server_config,
    };
    use ssh3_server::{ServerConfig, serve_connection};
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UdpSocket as TokioUdpSocket;
    use tokio::net::{TcpListener, TcpStream};
    #[cfg(unix)]
    use tokio::net::{UnixListener, UnixStream};
    #[cfg(unix)]
    use tokio::process::Command as TokioCommand;
    use tokio::time::{sleep, timeout};
    use url::Url;

    use super::{
        CapturedSession, ClientConfig, ClientError, LocalTerminalInfo, OidcConfig, OidcError,
        SessionRequest, TerminalSize, TrustStrategy, activate_client, build_session_runtime,
        client_bind_addr, client_quinn_config, connect_client, conversation_id_base64,
        resolve_target, run_capture_on_client, run_exec_capture,
        run_exec_capture_with_browser_opener, send_forward_agent_request,
        send_initial_session_requests, send_signal_request, send_window_change_request,
    };

    async fn setup_request_capture_harness(
        expected_messages: usize,
    ) -> (super::ActiveClient, tokio::task::JoinHandle<Vec<Message>>) {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut server = new_server(connection.clone()).await.unwrap();
            let mut accepted = timeout(
                Duration::from_secs(5),
                accept_server_conversation(&mut server, connection.clone(), 30_000, 10),
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap();
            assert!(is_ssh3_connect(&accepted.request));
            accepted
                .control_stream
                .send_response(
                    response_with_server_header(StatusCode::OK, SSH3_VERSION_STRING).unwrap(),
                )
                .await
                .unwrap();

            let (incoming_channel, send, recv) =
                timeout(Duration::from_secs(5), accept_bi_channel(&connection))
                    .await
                    .unwrap()
                    .unwrap();
            let channel = incoming_channel
                .into_accepted_channel_for_conversation(accepted.conversation.as_ref(), recv, send)
                .into_channel();
            channel.confirm_channel(30_000).await.unwrap();

            let mut messages = Vec::new();
            for _ in 0..expected_messages {
                messages.push(
                    timeout(Duration::from_secs(5), channel.next_message())
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }
            messages
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        let client = connect_client(&config).await.unwrap();
        (client, server_task)
    }

    async fn connect_client_with_authorization_builder(
        config: &ClientConfig,
        authorization_builder: impl FnOnce(&[u8; 32]) -> String,
    ) -> Result<super::ActiveClient, ClientError> {
        let resolved = resolve_target(&config.target_url, config.server_name.as_deref()).await?;
        let bind_addr = client_bind_addr(resolved.remote_addr);
        let mut endpoint = Endpoint::client(bind_addr).map_err(ClientError::Endpoint)?;
        endpoint.set_default_client_config(client_quinn_config(&config.trust)?);

        let connection = endpoint
            .connect(resolved.remote_addr, &resolved.server_name)
            .map_err(ClientError::Connect)?
            .await
            .map_err(ClientError::Connection)?;

        let (mut driver, mut send_request) = new_client(connection.clone()).await?;
        let driver_task = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let conversation_id = generate_conversation_id(&connection)?;
        let mut request = build_connect_request(config.target_url.clone(), &config.user_agent)?;
        if let Some(username) = config.username.as_deref() {
            request
                .headers_mut()
                .insert(SSH3_USER_HEADER, HeaderValue::from_str(username)?);
        }
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&authorization_builder(&conversation_id))?,
        );

        let established = establish_client_conversation(
            &mut send_request,
            connection.clone(),
            request,
            config.max_packet_size,
            config.default_datagrams_queue_size,
        )
        .await?;
        driver_task.abort();

        Ok(activate_client(
            endpoint,
            connection,
            send_request,
            driver_task,
            established,
            config.max_packet_size,
            config.default_datagrams_queue_size,
        ))
    }

    #[cfg(unix)]
    fn current_username() -> String {
        User::from_uid(Uid::current()).unwrap().unwrap().name
    }

    #[cfg(unix)]
    struct GoInteropBinaries {
        client: PathBuf,
        server: PathBuf,
    }

    #[cfg(unix)]
    struct GoAgentProbeBinary {
        path: PathBuf,
    }

    #[cfg(unix)]
    struct GoCliBinaries {
        client: PathBuf,
        server: PathBuf,
    }

    struct AuthFixture {
        _tempdir: TempDir,
        private_key_path: std::path::PathBuf,
        authorized_identities_path: std::path::PathBuf,
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
                ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[31; 32]))
            }
            AuthKeyAlgorithm::NistP256 => {
                let secret_key = P256SecretKey::from_slice(&[29; 32]).unwrap();
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

    #[cfg(unix)]
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[cfg(unix)]
    fn build_go_binary(package: &str, output_path: &Path) {
        let build_output = StdCommand::new("go")
            .arg("build")
            .arg("-mod=mod")
            .arg("-tags")
            .arg("disable_password_auth")
            .arg("-o")
            .arg(output_path)
            .arg(package)
            .current_dir(repo_root())
            .output()
            .unwrap();
        if !build_output.status.success() {
            panic!(
                "go build {} failed\nstdout:\n{}\nstderr:\n{}",
                package,
                String::from_utf8_lossy(&build_output.stdout),
                String::from_utf8_lossy(&build_output.stderr),
            );
        }
    }

    #[cfg(unix)]
    fn go_interop_binaries() -> &'static GoInteropBinaries {
        static BINARIES: OnceLock<GoInteropBinaries> = OnceLock::new();
        BINARIES.get_or_init(|| {
            let dir = repo_root().join("target/go-interop");
            fs::create_dir_all(&dir).unwrap();
            let client = dir.join("ssh3-go-interop-client");
            let server = dir.join("ssh3-go-interop-server");
            build_go_binary("./internal/interop/go_client", &client);
            build_go_binary("./internal/interop/go_server", &server);
            GoInteropBinaries { client, server }
        })
    }

    #[cfg(unix)]
    fn go_cli_binaries() -> &'static GoCliBinaries {
        static BINARIES: OnceLock<GoCliBinaries> = OnceLock::new();
        BINARIES.get_or_init(|| {
            let dir = repo_root().join("target/go-interop");
            fs::create_dir_all(&dir).unwrap();
            let client = dir.join("ssh3-go-cli");
            let server = dir.join("ssh3-go-server");
            build_go_binary("./cmd/ssh3", &client);
            build_go_binary("./cmd/ssh3-server", &server);
            GoCliBinaries { client, server }
        })
    }

    #[cfg(unix)]
    fn go_agent_probe_binary() -> &'static GoAgentProbeBinary {
        static BINARY: OnceLock<GoAgentProbeBinary> = OnceLock::new();
        BINARY.get_or_init(|| {
            let dir = repo_root().join("target/go-interop");
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("ssh3-agent-probe");
            build_go_binary("./internal/interop/agent_probe", &path);
            GoAgentProbeBinary { path }
        })
    }

    #[cfg(unix)]
    fn reserve_udp_port() -> u16 {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.local_addr().unwrap().port()
    }

    #[cfg(unix)]
    fn reserve_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    #[cfg(unix)]
    async fn spawn_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = [0; 4096];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    if n == 0 {
                        return;
                    }
                    let _ = stream.write_all(&buf[..n]).await;
                    let _ = stream.flush().await;
                });
            }
        });
        (addr, task)
    }

    #[cfg(unix)]
    async fn spawn_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket =
            TokioUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(result) => result,
                    Err(_) => return,
                };
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        });
        (addr, task)
    }

    #[cfg(unix)]
    async fn spawn_go_interop_server(
        bind_addr: &str,
        username: &str,
        authorized_identity_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> (tokio::process::Child, SocketAddr) {
        let binaries = go_interop_binaries();
        let mut child = TokioCommand::new(&binaries.server)
            .arg("--bind")
            .arg(bind_addr)
            .arg("--url-path")
            .arg("/ssh3-term")
            .arg("--user")
            .arg(username)
            .arg("--authorized-identity")
            .arg(authorized_identity_path)
            .arg("--cert")
            .arg(cert_path)
            .arg("--key")
            .arg(key_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let stdout = child.stdout.take().unwrap();
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut ready_line = String::new();
        let bytes_read = timeout(Duration::from_secs(10), reader.read_line(&mut ready_line))
            .await
            .unwrap()
            .unwrap();
        assert!(
            bytes_read > 0,
            "go interop server exited before signaling readiness"
        );
        let ready_line = ready_line.trim();
        let (_, bind_addr) = ready_line
            .split_once(' ')
            .unwrap_or_else(|| panic!("unexpected go interop server readiness line: {ready_line}"));
        let bind_addr = bind_addr.parse::<SocketAddr>().unwrap_or_else(|err| {
            panic!("invalid go interop server bind address {bind_addr}: {err}")
        });
        drop(reader);
        (child, bind_addr)
    }

    #[cfg(unix)]
    async fn run_go_interop_client(
        url: &str,
        username: &str,
        private_key_path: &Path,
        command: &str,
    ) -> std::process::Output {
        let binaries = go_interop_binaries();
        timeout(
            Duration::from_secs(20),
            TokioCommand::new(&binaries.client)
                .arg("--url")
                .arg(url)
                .arg("--user")
                .arg(username)
                .arg("--privkey")
                .arg(private_key_path)
                .arg("--insecure")
                .arg(command)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    }

    #[cfg(unix)]
    async fn spawn_go_cli_server(
        bind_addr: &str,
        username: &str,
        home_dir: &Path,
        cert_path: &Path,
        key_path: &Path,
        log_path: &Path,
    ) -> tokio::process::Child {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir).unwrap();
        let stderr_log = fs::File::create(log_path).unwrap();
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut child = TokioCommand::new(&binaries.server)
            .arg("-bind")
            .arg(bind_addr)
            .arg("-v")
            .arg("-url-path")
            .arg("/ssh3-term")
            .arg("-generate-selfsigned-cert")
            .arg("-cert")
            .arg(cert_path)
            .arg("-key")
            .arg(key_path)
            .env("HOME", home_dir)
            .env("USER", username)
            .env("LOGNAME", username)
            .env("SHELL", shell)
            // the server resolves the session user through getpwnam, so its
            // identity files would come from the real /etc/passwd home; point
            // it at the fixture home instead (unix_util honors this override)
            .env("SSH3_USER_HOME", home_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let ready_line = format!("Server started, listening on {bind_addr}/ssh3-term");
        timeout(Duration::from_secs(20), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let logs = fs::read_to_string(log_path).unwrap_or_default();
                    panic!(
                        "go CLI server exited before signaling readiness with status {status}\nlogs:\n{logs}"
                    );
                }

                let logs = fs::read_to_string(log_path).unwrap_or_default();
                if logs.contains(&ready_line) {
                    break;
                }

                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        child
    }

    #[cfg(unix)]
    async fn spawn_go_cli_tcp_forwarder(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        local_port: u16,
        remote_addr: SocketAddr,
        log_path: &Path,
    ) -> tokio::process::Child {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        let stderr_log = fs::File::create(log_path).unwrap();
        let forward_spec = format!("{local_port}/{}@{}", remote_addr.ip(), remote_addr.port());
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg("-forward-tcp")
            .arg(&forward_spec)
            .arg(url)
            .arg("sleep")
            .arg("8")
            .env("HOME", home_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port));
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let logs = fs::read_to_string(log_path).unwrap_or_default();
                    panic!(
                        "go CLI forwarder exited before the local port was reachable with status {status}\nlogs:\n{logs}"
                    );
                }

                if TcpStream::connect(local_addr).await.is_ok() {
                    break;
                }

                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        child
    }

    #[cfg(unix)]
    async fn spawn_go_cli_udp_forwarder(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        local_port: u16,
        remote_addr: SocketAddr,
        log_path: &Path,
    ) -> tokio::process::Child {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        let stderr_log = fs::File::create(log_path).unwrap();
        let forward_spec = format!("{local_port}/{}@{}", remote_addr.ip(), remote_addr.port());
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg("-forward-udp")
            .arg(&forward_spec)
            .arg(url)
            .arg("sleep")
            .arg("8")
            .env("HOME", home_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port));
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let logs = fs::read_to_string(log_path).unwrap_or_default();
                    panic!(
                        "go CLI UDP forwarder exited before the local port was bound with status {status}\nlogs:\n{logs}"
                    );
                }

                match UdpSocket::bind(local_addr) {
                    Ok(socket) => drop(socket),
                    Err(err) if err.kind() == io::ErrorKind::AddrInUse => break,
                    Err(err) => panic!(
                        "could not probe local UDP forwarder port {local_addr}: {err}"
                    ),
                }

                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();

        child
    }

    #[cfg(unix)]
    async fn run_go_cli_client(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        command: &[&str],
    ) -> std::process::Output {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        timeout(
            Duration::from_secs(20),
            TokioCommand::new(&binaries.client)
                .arg("-insecure")
                .arg("-privkey")
                .arg(private_key_path)
                .arg(url)
                .args(command)
                .env("HOME", home_dir)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    }

    #[cfg(unix)]
    async fn run_go_cli_client_with_forwarded_agent(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        agent_socket: &Path,
        command: &[&str],
    ) -> std::process::Output {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-v")
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg("-forward-agent")
            .arg(url)
            .args(command)
            .env("HOME", home_dir)
            .env("SSH_AUTH_SOCK", agent_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let stdout_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stdout.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stderr.read_to_end(&mut buf).await.unwrap();
            buf
        });

        match timeout(Duration::from_secs(30), child.wait()).await {
            Ok(status) => std::process::Output {
                status: status.unwrap(),
                stdout: stdout_task.await.unwrap(),
                stderr: stderr_task.await.unwrap(),
            },
            Err(_) => {
                let _ = child.kill().await;
                let status = child.wait().await.unwrap();
                let output = std::process::Output {
                    status,
                    stdout: stdout_task.await.unwrap(),
                    stderr: stderr_task.await.unwrap(),
                };
                panic!(
                    "go client with forwarded agent timed out\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        }
    }

    #[cfg(unix)]
    async fn run_go_cli_client_with_oidc(
        home_dir: &Path,
        url: &str,
        issuer_url: &str,
        oidc_config_path: &Path,
        command: &[&str],
    ) -> std::process::Output {
        let binaries = go_cli_binaries();
        let browser_dir = home_dir.join("browser-bin");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        fs::create_dir_all(&browser_dir).unwrap();

        let fake_browser = browser_dir.join("xdg-open");
        fs::write(
            &fake_browser,
            "#!/bin/sh\nexec curl -fsSL \"$1\" >/dev/null\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake_browser, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let path = std::env::var("PATH").unwrap_or_default();
        let mut child = TokioCommand::new(&binaries.client)
            .arg("-v")
            .arg("-insecure")
            .arg("-use-oidc")
            .arg(issuer_url)
            .arg("-oidc-config")
            .arg(oidc_config_path)
            .arg(url)
            .args(command)
            .env("HOME", home_dir)
            .env("PATH", format!("{}:{path}", browser_dir.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut stdout = child.stdout.take().unwrap();
        let stdout_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stdout.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let mut stderr = child.stderr.take().unwrap();
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            stderr.read_to_end(&mut buf).await.unwrap();
            buf
        });

        match timeout(Duration::from_secs(20), child.wait()).await {
            Ok(status) => std::process::Output {
                status: status.unwrap(),
                stdout: stdout_task.await.unwrap(),
                stderr: stderr_task.await.unwrap(),
            },
            Err(_) => {
                let _ = child.kill().await;
                let status = child.wait().await.unwrap();
                let output = std::process::Output {
                    status,
                    stdout: stdout_task.await.unwrap(),
                    stderr: stderr_task.await.unwrap(),
                };
                panic!(
                    "go client with oidc timed out\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
        }
    }

    #[cfg(unix)]
    async fn run_go_cli_client_with_password(
        home_dir: &Path,
        url: &str,
        password: &str,
        command: &[&str],
    ) -> std::process::Output {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();

        let mut parts = vec![
            shell_quote(binaries.client.to_string_lossy().as_ref()),
            "-insecure".to_string(),
            "-use-password".to_string(),
            shell_quote(url),
        ];
        parts.extend(command.iter().map(|arg| shell_quote(arg)));
        let command = parts.join(" ");

        let mut child = TokioCommand::new("script")
            .arg("-qefc")
            .arg(command)
            .arg("/dev/null")
            .env("HOME", home_dir)
            .env("TERM", "xterm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let mut stdin = child.stdin.take().unwrap();
        stdin
            .write_all(format!("{password}\n").as_bytes())
            .await
            .unwrap();
        drop(stdin);

        timeout(Duration::from_secs(20), child.wait_with_output())
            .await
            .unwrap()
            .unwrap()
    }

    #[cfg(unix)]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }

    #[cfg(unix)]
    struct GoCliPtySession {
        child: tokio::process::Child,
        writer: Arc<Mutex<StdFile>>,
        controller: StdFile,
        output: Arc<Mutex<Vec<u8>>>,
        output_task: tokio::task::JoinHandle<io::Result<()>>,
    }

    #[cfg(unix)]
    impl GoCliPtySession {
        async fn write_all(&self, input: &str) {
            let writer = self.writer.clone();
            let input = input.as_bytes().to_vec();
            tokio::task::spawn_blocking(move || -> io::Result<()> {
                let mut writer = writer.lock().unwrap();
                writer.write_all(&input)?;
                writer.flush()?;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        }

        fn resize(&self, size: TerminalSize) -> io::Result<()> {
            let winsize = Winsize {
                ws_row: size.char_height,
                ws_col: size.char_width,
                ws_xpixel: size.pixel_width,
                ws_ypixel: size.pixel_height,
            };
            let result = unsafe {
                nix::libc::ioctl(self.controller.as_raw_fd(), nix::libc::TIOCSWINSZ, &winsize)
            };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn send_signal(&self, signal: i32) -> io::Result<()> {
            let pid = self
                .child
                .id()
                .ok_or_else(|| io::Error::other("go CLI PTY child has no pid"))?
                as i32;
            let result = unsafe { nix::libc::kill(pid, signal) };
            if result == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn output_string(&self) -> String {
            String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
        }

        async fn wait_for_output_fragment(&self, fragment: &str) {
            let fragment = fragment.to_string();
            timeout(Duration::from_secs(10), async {
                loop {
                    if self.output_string().replace('\r', "").contains(&fragment) {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap();
        }

        async fn wait_with_output(mut self) -> std::process::Output {
            let status = timeout(Duration::from_secs(20), self.child.wait())
                .await
                .unwrap()
                .unwrap();
            self.output_task.await.unwrap().unwrap();
            std::process::Output {
                status,
                stdout: self.output.lock().unwrap().clone(),
                stderr: Vec::new(),
            }
        }
    }

    #[cfg(unix)]
    fn pty_eof(err: &io::Error) -> bool {
        matches!(err.raw_os_error(), Some(code) if code == nix::libc::EIO)
    }

    #[cfg(unix)]
    async fn spawn_go_cli_shell_with_pty(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        initial_size: TerminalSize,
    ) -> GoCliPtySession {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();

        let openpty = openpty(
            Some(&Winsize {
                ws_row: initial_size.char_height,
                ws_col: initial_size.char_width,
                ws_xpixel: initial_size.pixel_width,
                ws_ypixel: initial_size.pixel_height,
            }),
            None,
        )
        .unwrap();
        let master = StdFile::from(openpty.master);
        let slave = StdFile::from(openpty.slave);

        let mut child = TokioCommand::new(&binaries.client);
        child
            .arg("-insecure")
            .arg("-privkey")
            .arg(private_key_path)
            .arg(url)
            .env("HOME", home_dir)
            .env("TERM", "xterm")
            .kill_on_drop(true);

        let slave_fd = slave.as_raw_fd();
        child
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        unsafe {
            child.pre_exec(move || {
                if nix::libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                if nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = child.spawn().unwrap();
        drop(slave);

        let output = Arc::new(Mutex::new(Vec::new()));
        let output_reader = output.clone();
        let mut reader = master.try_clone().unwrap();
        let writer = Arc::new(Mutex::new(master.try_clone().unwrap()));
        let output_task = tokio::task::spawn_blocking(move || -> io::Result<()> {
            let mut chunk = [0_u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => return Ok(()),
                    Ok(n) => output_reader.lock().unwrap().extend_from_slice(&chunk[..n]),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) if pty_eof(&err) => return Ok(()),
                    Err(err) => return Err(err),
                }
            }
        });

        GoCliPtySession {
            child,
            writer,
            controller: master,
            output,
            output_task,
        }
    }

    #[cfg(unix)]
    async fn run_go_cli_shell(
        home_dir: &Path,
        url: &str,
        private_key_path: &Path,
        input: &str,
    ) -> std::process::Output {
        let binaries = go_cli_binaries();
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();

        let command = format!(
            "{} -insecure -privkey {} {}",
            shell_quote(binaries.client.to_string_lossy().as_ref()),
            shell_quote(private_key_path.to_string_lossy().as_ref()),
            shell_quote(url),
        );

        let mut child = TokioCommand::new("script")
            .arg("-qefc")
            .arg(command)
            .arg("/dev/null")
            .env("HOME", home_dir)
            .env("TERM", "xterm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input.as_bytes()).await.unwrap();
        drop(stdin);

        timeout(Duration::from_secs(20), child.wait_with_output())
            .await
            .unwrap()
            .unwrap()
    }

    async fn run_shell_capture_with_resize_on_client(
        client: &super::ActiveClient,
        initial_terminal: LocalTerminalInfo,
        resized_terminal: TerminalSize,
        shell_input_prefix: &str,
        shell_input_suffix: &str,
    ) -> Result<CapturedSession, ClientError> {
        let channel = client.open_session_channel().await?;
        send_initial_session_requests(
            channel.as_ref(),
            &SessionRequest::Shell,
            Some(&initial_terminal),
        )
        .await?;
        channel
            .write_data(shell_input_prefix.as_bytes(), SSH_EXTENDED_DATA_NONE)
            .await
            .map_err(ClientError::from)?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let initial_size_fragment = format!(
            "{} {}",
            initial_terminal.size.char_height, initial_terminal.size.char_width
        );
        let mut resize_sent = false;

        loop {
            match timeout(Duration::from_secs(10), channel.next_message())
                .await
                .unwrap()?
            {
                Message::Data(data) => {
                    match data.data_type {
                        SSH_EXTENDED_DATA_NONE => stdout.extend_from_slice(&data.data),
                        ssh3_proto::SSH_EXTENDED_DATA_STDERR => {
                            stderr.extend_from_slice(&data.data)
                        }
                        _ => {}
                    }
                    if !resize_sent
                        && String::from_utf8_lossy(&stdout).contains(&initial_size_fragment)
                    {
                        send_window_change_request(channel.as_ref(), resized_terminal).await?;
                        channel
                            .write_data(shell_input_suffix.as_bytes(), SSH_EXTENDED_DATA_NONE)
                            .await
                            .map_err(ClientError::from)?;
                        resize_sent = true;
                    }
                }
                Message::ChannelRequest(message) => match message.request {
                    ChannelRequest::ExitStatus(status) => {
                        return Ok(CapturedSession {
                            server_header: client.server_header.clone(),
                            exit_status: status.exit_status as i32,
                            stdout,
                            stderr,
                        });
                    }
                    ChannelRequest::ExitSignal(signal) => {
                        return Err(ClientError::ExitSignal(signal));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    async fn run_tcp_forwarding_round_trip_on_client(
        client: &super::ActiveClient,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let channel = open_tcp_forwarding_channel(
            client.conversation.as_ref(),
            &client.connection,
            client.max_packet_size,
            client.default_datagrams_queue_size,
            remote_addr,
        )
        .await
        .map_err(ClientError::from)?;
        channel
            .write_data(payload, SSH_EXTENDED_DATA_NONE)
            .await
            .map_err(ClientError::from)?;

        loop {
            match timeout(Duration::from_secs(10), channel.next_message())
                .await
                .unwrap()?
            {
                Message::Data(data) if data.data_type == SSH_EXTENDED_DATA_NONE => {
                    let _ = channel.close().await;
                    return Ok(data.data);
                }
                _ => {}
            }
        }
    }

    async fn run_udp_forwarding_round_trip_on_client(
        client: &super::ActiveClient,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let channel = open_udp_forwarding_channel(
            client.conversation.as_ref(),
            &client.connection,
            client.max_packet_size,
            client.default_datagrams_queue_size,
            remote_addr,
        )
        .await
        .map_err(ClientError::from)?;
        channel
            .send_datagram(payload.to_vec())
            .await
            .map_err(ClientError::from)?;
        let echoed = timeout(Duration::from_secs(10), channel.receive_datagram())
            .await
            .unwrap();
        let _ = channel.close().await;
        Ok(echoed)
    }

    fn create_auth_fixture(algorithm: AuthKeyAlgorithm) -> AuthFixture {
        let tempdir = TempDir::new().unwrap();
        let private_key_path = tempdir.path().join("id_ed25519");
        let authorized_identities_path = tempdir.path().join("authorized_keys");
        let private_key = auth_private_key(algorithm);
        private_key
            .write_openssh_file(&private_key_path, ssh_key::LineEnding::LF)
            .unwrap();
        fs::write(
            &authorized_identities_path,
            format!("{}\n", private_key.public_key().to_openssh().unwrap()),
        )
        .unwrap();

        AuthFixture {
            _tempdir: tempdir,
            private_key_path,
            authorized_identities_path,
            username: {
                #[cfg(unix)]
                {
                    current_username()
                }
                #[cfg(not(unix))]
                {
                    "user".to_string()
                }
            },
        }
    }

    #[cfg(unix)]
    fn go_binary_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(unix)]
    fn lock_go_binary_tests() -> std::sync::MutexGuard<'static, ()> {
        go_binary_test_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(unix)]
    const SSH_AGENT_FAILURE: u8 = 5;
    #[cfg(unix)]
    const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
    #[cfg(unix)]
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    #[cfg(unix)]
    const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
    #[cfg(unix)]
    const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
    #[cfg(unix)]
    const SSH_AGENT_RSA_SHA2_256: u32 = 2;

    #[cfg(unix)]
    struct MockAgent {
        _tempdir: TempDir,
        socket_path: PathBuf,
        sign_flags: Arc<Mutex<Vec<u32>>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl MockAgent {
        fn sign_flags(&self) -> Vec<u32> {
            self.sign_flags.lock().unwrap().clone()
        }
    }

    #[cfg(unix)]
    impl Drop for MockAgent {
        fn drop(&mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    #[cfg(unix)]
    async fn spawn_mock_agent(private_key: ssh_key::PrivateKey) -> MockAgent {
        let tempdir = TempDir::new().unwrap();
        let socket_path = tempdir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let private_key = Arc::new(private_key);
        let sign_flags = Arc::new(Mutex::new(Vec::new()));
        let sign_flags_task = sign_flags.clone();

        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let private_key = private_key.clone();
                let sign_flags = sign_flags_task.clone();

                tokio::spawn(async move {
                    loop {
                        let request = match read_agent_message(&mut stream).await {
                            Ok(Some(request)) => request,
                            Ok(None) => break,
                            Err(err)
                                if matches!(
                                    err.kind(),
                                    io::ErrorKind::BrokenPipe
                                        | io::ErrorKind::ConnectionAborted
                                        | io::ErrorKind::ConnectionReset
                                        | io::ErrorKind::UnexpectedEof
                                ) =>
                            {
                                break;
                            }
                            Err(err) => panic!("mock agent read failed: {err}"),
                        };
                        let response =
                            handle_agent_request(&private_key, &sign_flags, request.as_slice())
                                .unwrap();
                        if let Err(err) =
                            write_agent_message(&mut stream, response.as_slice()).await
                        {
                            if matches!(
                                err.kind(),
                                io::ErrorKind::BrokenPipe
                                    | io::ErrorKind::ConnectionAborted
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::UnexpectedEof
                            ) {
                                break;
                            }
                            panic!("mock agent write failed: {err}");
                        }
                    }
                });
            }
        });

        MockAgent {
            _tempdir: tempdir,
            socket_path,
            sign_flags,
            task: Some(task),
        }
    }

    #[cfg(unix)]
    async fn read_agent_message(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
        let mut len = [0u8; 4];
        match stream.read_exact(&mut len).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err),
        }

        let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut payload).await?;
        Ok(Some(payload))
    }

    #[cfg(unix)]
    async fn write_agent_message(stream: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
        let len = u32::try_from(payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "mock SSH agent payload exceeds u32 length",
            )
        })?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(payload).await
    }

    #[cfg(unix)]
    fn handle_agent_request(
        private_key: &ssh_key::PrivateKey,
        sign_flags: &Arc<Mutex<Vec<u32>>>,
        request: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut cursor = request;
        let message = match take_agent_byte(&mut cursor)? {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                if !cursor.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in mock agent identities request",
                    ));
                }

                let key_blob = private_key
                    .public_key()
                    .to_bytes()
                    .map_err(mock_agent_ssh_key_error)?;
                let mut response = vec![SSH_AGENT_IDENTITIES_ANSWER];
                response.extend_from_slice(&1u32.to_be_bytes());
                append_agent_string(&mut response, key_blob.as_slice());
                append_agent_string(&mut response, b"mock-agent");
                response
            }
            SSH_AGENTC_SIGN_REQUEST => {
                let key_blob = take_agent_string(&mut cursor)?;
                let signing_input = take_agent_string(&mut cursor)?;
                let flags = take_agent_u32(&mut cursor)?;
                if !cursor.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in mock agent sign request",
                    ));
                }

                let expected_key_blob = private_key
                    .public_key()
                    .to_bytes()
                    .map_err(mock_agent_ssh_key_error)?;
                if key_blob != expected_key_blob {
                    return Ok(vec![SSH_AGENT_FAILURE]);
                }

                sign_flags.lock().unwrap().push(flags);
                let signature = mock_agent_signature(private_key, signing_input.as_slice(), flags)?;
                let mut response = vec![SSH_AGENT_SIGN_RESPONSE];
                append_agent_string(&mut response, signature.as_slice());
                response
            }
            _ => vec![SSH_AGENT_FAILURE],
        };

        Ok(message)
    }

    #[cfg(unix)]
    fn mock_agent_signature(
        private_key: &ssh_key::PrivateKey,
        signing_input: &[u8],
        flags: u32,
    ) -> io::Result<Vec<u8>> {
        let signature = match private_key.key_data() {
            KeypairData::Ed25519(_) => {
                if flags != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unexpected Ed25519 agent sign flags: {flags}"),
                    ));
                }
                Signer::try_sign(private_key, signing_input)
                    .map_err(|_| io::Error::other("could not sign mock Ed25519 agent request"))?
            }
            KeypairData::Rsa(keypair) => {
                if flags != SSH_AGENT_RSA_SHA2_256 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unexpected RSA agent sign flags: {flags}"),
                    ));
                }
                let signing_key =
                    RsaSigningKey::<Sha256>::new(mock_agent_rsa_private_key(keypair)?);
                let signature: RsaSignature = Signer::try_sign(&signing_key, signing_input)
                    .map_err(|_| io::Error::other("could not sign mock RSA agent request"))?;
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    signature.to_vec(),
                )
                .map_err(mock_agent_ssh_key_error)?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mock agent only supports Ed25519 and RSA keys",
                ));
            }
        };

        Vec::<u8>::try_from(signature).map_err(mock_agent_ssh_key_error)
    }

    #[cfg(unix)]
    fn take_agent_byte(cursor: &mut &[u8]) -> io::Result<u8> {
        let Some((&byte, rest)) = cursor.split_first() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated mock SSH agent message",
            ));
        };
        *cursor = rest;
        Ok(byte)
    }

    #[cfg(unix)]
    fn take_agent_u32(cursor: &mut &[u8]) -> io::Result<u32> {
        if cursor.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated mock SSH agent u32",
            ));
        }
        let (prefix, rest) = cursor.split_at(4);
        *cursor = rest;
        Ok(u32::from_be_bytes(prefix.try_into().unwrap()))
    }

    #[cfg(unix)]
    fn take_agent_string(cursor: &mut &[u8]) -> io::Result<Vec<u8>> {
        let len = take_agent_u32(cursor)? as usize;
        if cursor.len() < len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated mock SSH agent string",
            ));
        }
        let (value, rest) = cursor.split_at(len);
        *cursor = rest;
        Ok(value.to_vec())
    }

    #[cfg(unix)]
    fn append_agent_string(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }

    #[cfg(unix)]
    fn mock_agent_ssh_key_error(err: ssh_key::Error) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }

    #[cfg(unix)]
    fn mock_agent_rsa_private_key(keypair: &RsaKeypair) -> io::Result<JwtRsaPrivateKey> {
        let private_key = JwtRsaPrivateKey::from_components(
            mock_agent_rsa_biguint(keypair.public.n.as_positive_bytes())?,
            mock_agent_rsa_biguint(keypair.public.e.as_positive_bytes())?,
            mock_agent_rsa_biguint(keypair.private.d.as_positive_bytes())?,
            vec![
                mock_agent_rsa_biguint(keypair.private.p.as_positive_bytes())?,
                mock_agent_rsa_biguint(keypair.private.q.as_positive_bytes())?,
            ],
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RSA private key"))?;
        private_key
            .validate()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RSA private key"))?;
        Ok(private_key)
    }

    #[cfg(unix)]
    fn mock_agent_rsa_biguint(bytes: Option<&[u8]>) -> io::Result<RsaBigUint> {
        let bytes = bytes.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid RSA key component")
        })?;
        Ok(RsaBigUint::from_bytes_be(bytes))
    }

    async fn read_stdout_line(channel: &Arc<Channel>) -> Result<String, ClientError> {
        let mut stdout = Vec::new();
        loop {
            match channel.next_message().await? {
                Message::Data(data) if data.data_type == SSH_EXTENDED_DATA_NONE => {
                    stdout.extend_from_slice(&data.data);
                    if let Some(newline) = stdout.iter().position(|byte| *byte == b'\n') {
                        return Ok(String::from_utf8_lossy(&stdout[..newline]).to_string());
                    }
                }
                Message::ChannelRequest(message) => match message.request {
                    ChannelRequest::ExitStatus(status) => {
                        return Err(ClientError::Io(io::Error::other(format!(
                            "session exited before producing stdout line: {}",
                            status.exit_status
                        ))));
                    }
                    ChannelRequest::ExitSignal(signal) => {
                        return Err(ClientError::ExitSignal(signal));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    #[cfg(unix)]
    async fn request_forwarded_agent_signature(
        socket_path: &str,
        signing_input: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut forwarded_socket = UnixStream::connect(socket_path.trim()).await?;
        write_agent_message(&mut forwarded_socket, &[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
        let identities = read_agent_message(&mut forwarded_socket)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "forwarded agent closed before returning identities",
                )
            })?;
        let mut cursor = identities.as_slice();
        if take_agent_byte(&mut cursor)? != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected forwarded agent identities response",
            ));
        }
        if take_agent_u32(&mut cursor)? != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected forwarded agent identity count",
            ));
        }
        let key_blob = take_agent_string(&mut cursor)?;
        let _comment = take_agent_string(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in forwarded agent identities response",
            ));
        }

        let mut sign_request = vec![SSH_AGENTC_SIGN_REQUEST];
        append_agent_string(&mut sign_request, &key_blob);
        append_agent_string(&mut sign_request, signing_input);
        sign_request.extend_from_slice(&0u32.to_be_bytes());
        write_agent_message(&mut forwarded_socket, &sign_request).await?;
        let signature = read_agent_message(&mut forwarded_socket)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "forwarded agent closed before returning a signature",
                )
            })?;
        let mut cursor = signature.as_slice();
        if take_agent_byte(&mut cursor)? != SSH_AGENT_SIGN_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected forwarded agent sign response",
            ));
        }
        let signature_blob = take_agent_string(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes in forwarded agent sign response",
            ));
        }
        Ok(signature_blob)
    }

    struct OidcFixture {
        _tempdir: TempDir,
        authorized_identities_path: std::path::PathBuf,
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
        fn bearer_token_for_nonce(&self, nonce: &str) -> String {
            build_oidc_token(
                &self.issuer_url,
                &self.client_id,
                &self.email,
                Some(nonce),
                &self.signing_key,
            )
        }
    }

    struct HttpRequest {
        method: String,
        target: String,
        body: Vec<u8>,
    }

    async fn read_http_request(
        stream: &mut tokio::net::TcpStream,
    ) -> Result<HttpRequest, std::io::Error> {
        let mut buffer = Vec::new();
        let mut header_end = None;
        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = buffer.windows(4).position(|window| window == b"\r\n\r\n");
            }
            if let Some(header_end) = header_end {
                let header_text = String::from_utf8_lossy(&buffer[..header_end]);
                let content_length = header_text
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                if buffer.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }

        let header_end = header_end.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "missing HTTP headers")
        })?;
        let header_text = String::from_utf8_lossy(&buffer[..header_end]);
        let mut request_line = header_text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let method = request_line.next().unwrap_or_default().to_string();
        let target = request_line.next().unwrap_or("/").to_string();
        let content_length = header_text
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);

        Ok(HttpRequest {
            method,
            target,
            body: buffer[header_end + 4..header_end + 4 + content_length].to_vec(),
        })
    }

    fn http_query_value(target: &str, key: &str) -> Option<String> {
        let url = Url::parse(&format!("http://localhost{target}")).ok()?;
        url.query_pairs()
            .find_map(|(current_key, value)| (current_key == key).then(|| value.into_owned()))
    }

    fn http_response(
        status_line: &str,
        content_type: &str,
        body: impl AsRef<str>,
        extra_headers: &[(&str, &str)],
    ) -> String {
        let body = body.as_ref();
        let mut response = format!(
            "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n",
            body.len()
        );
        for (name, value) in extra_headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        response.push_str(body);
        response
    }

    fn mock_browser_opener(url: String) -> Result<(), OidcError> {
        tokio::spawn(async move {
            let _ = reqwest::Client::new().get(url).send().await;
        });
        Ok(())
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
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_vec())
        )
    }

    async fn create_oidc_fixture() -> OidcFixture {
        let tempdir = TempDir::new().unwrap();
        let authorized_identities_path = tempdir.path().join("authorized_identities");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let issuer_url = format!("http://{}", listener.local_addr().unwrap());
        let client_id = "ssh3-client-id".to_string();
        let email = "alice@example.com";
        let signing_key = JwtRsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = signing_key.to_public_key();
        let discovery_body = format!(
            r#"{{"issuer":"{issuer_url}","jwks_uri":"{issuer_url}/keys","authorization_endpoint":"{issuer_url}/authorize","token_endpoint":"{issuer_url}/token"}}"#
        );
        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"test-key","alg":"RS256","n":"{}","e":"{}"}}]}}"#,
            URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        );
        let expected_challenge = Arc::new(Mutex::new(None::<String>));
        let expected_nonce = Arc::new(Mutex::new(None::<String>));
        let provider_task = tokio::spawn({
            let expected_challenge = expected_challenge.clone();
            let expected_nonce = expected_nonce.clone();
            let client_id = client_id.clone();
            let issuer_url = issuer_url.clone();
            let signing_key = signing_key.clone();
            async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let discovery_body = discovery_body.clone();
                    let jwks_body = jwks_body.clone();
                    let token_body = format!(
                        r#"{{"access_token":"mock-access-token","token_type":"Bearer","id_token":"{}"}}"#,
                        build_oidc_token(
                            &issuer_url,
                            &client_id,
                            email,
                            expected_nonce.lock().unwrap().as_deref(),
                            &signing_key,
                        )
                    );
                    let expected_challenge = expected_challenge.clone();
                    let expected_nonce = expected_nonce.clone();
                    let client_id = client_id.clone();
                    tokio::spawn(async move {
                        let request = read_http_request(&mut stream).await.unwrap();
                        let response = match request.target.split('?').next().unwrap_or("/") {
                            "/.well-known/openid-configuration" => http_response(
                                "HTTP/1.1 200 OK",
                                "application/json",
                                discovery_body,
                                &[],
                            ),
                            "/keys" => {
                                http_response("HTTP/1.1 200 OK", "application/json", jwks_body, &[])
                            }
                            "/authorize" => {
                                assert_eq!(request.method, "GET");
                                assert_eq!(
                                    http_query_value(&request.target, "client_id").as_deref(),
                                    Some(client_id.as_str())
                                );
                                assert_eq!(
                                    http_query_value(&request.target, "scope").as_deref(),
                                    Some(super::DEFAULT_OIDC_SCOPE)
                                );
                                assert_eq!(
                                    http_query_value(&request.target, "code_challenge_method")
                                        .as_deref(),
                                    Some("S256")
                                );
                                *expected_challenge.lock().unwrap() =
                                    http_query_value(&request.target, "code_challenge");
                                *expected_nonce.lock().unwrap() =
                                    http_query_value(&request.target, "nonce");
                                let redirect_uri =
                                    http_query_value(&request.target, "redirect_uri").unwrap();
                                let state = http_query_value(&request.target, "state").unwrap();
                                let location =
                                    format!("{redirect_uri}?code=mock-auth-code&state={state}");
                                http_response(
                                    "HTTP/1.1 302 Found",
                                    "text/plain",
                                    "",
                                    &[("location", &location)],
                                )
                            }
                            "/token" => {
                                assert_eq!(request.method, "POST");
                                let form = url::form_urlencoded::parse(&request.body)
                                    .into_owned()
                                    .collect::<Vec<_>>();
                                let get = |name: &str| {
                                    form.iter().find_map(|(key, value)| {
                                        (key == name).then_some(value.clone())
                                    })
                                };
                                assert_eq!(
                                    get("grant_type").as_deref(),
                                    Some("authorization_code")
                                );
                                assert_eq!(get("code").as_deref(), Some("mock-auth-code"));
                                if let Some(token_client_id) = get("client_id") {
                                    assert_eq!(token_client_id, client_id);
                                }
                                let verifier = get("code_verifier").unwrap();
                                let expected = expected_challenge.lock().unwrap().clone().unwrap();
                                assert_eq!(super::oidc_code_challenge(&verifier), expected);
                                http_response(
                                    "HTTP/1.1 200 OK",
                                    "application/json",
                                    token_body,
                                    &[],
                                )
                            }
                            _ => http_response(
                                "HTTP/1.1 404 Not Found",
                                "application/json",
                                "{}",
                                &[],
                            ),
                        };
                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
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
            client_id: client_id.clone(),
            email: email.to_string(),
            signing_key,
            username: {
                #[cfg(unix)]
                {
                    current_username()
                }
                #[cfg(not(unix))]
                {
                    "user".to_string()
                }
            },
            provider_task,
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_against_the_rust_server() {
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, ServerConfig::default()),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'hello from client\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"hello from client\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_capture_round_trips_against_the_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");

        let (mut server, bind_addr) = spawn_go_interop_server(
            "127.0.0.1:0",
            &fixture.username,
            &fixture.authorized_identities_path,
            &cert_path,
            &key_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!("https://127.0.0.1:{}/ssh3-term", bind_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(40),
            run_exec_capture(&config, "printf 'hello from rust to go\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(session.exit_status, 0);
        assert_eq!(session.stdout, b"hello from rust to go\n".to_vec());
        assert!(session.stderr.is_empty());
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH "))
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_capture_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let mut server = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(20),
            run_exec_capture(&config, "echo hello from rust to real go"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(session.exit_status, 0);
        assert_eq!(session.stdout, b"hello from rust to real go\n".to_vec());
        assert!(session.stderr.is_empty(), "{session:?}");
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH "))
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_capture_round_trips_with_extra_pubkey_algorithms_against_the_real_go_server()
     {
        let _guard = lock_go_binary_tests();

        for (algorithm, label) in [
            (AuthKeyAlgorithm::NistP256, "p256"),
            (AuthKeyAlgorithm::Rsa, "rsa"),
        ] {
            let fixture = create_auth_fixture(algorithm);
            let tempdir = TempDir::new().unwrap();
            let home_dir = tempdir.path().join("home");
            fs::create_dir_all(home_dir.join(".ssh")).unwrap();
            fs::write(
                home_dir.join(".ssh").join("authorized_keys"),
                fs::read(&fixture.authorized_identities_path).unwrap(),
            )
            .unwrap();

            let bind_port = reserve_udp_port();
            let bind_addr = format!("127.0.0.1:{bind_port}");
            let cert_path = tempdir.path().join("cert.pem");
            let key_path = tempdir.path().join("key.pem");
            let log_path = tempdir.path().join("go-server.log");

            let mut server = spawn_go_cli_server(
                &bind_addr,
                &fixture.username,
                &home_dir,
                &cert_path,
                &key_path,
                &log_path,
            )
            .await;

            let mut config = ClientConfig::new(
                format!(
                    "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                    fixture.username
                )
                .parse()
                .unwrap(),
            );
            config.trust = TrustStrategy::Insecure;
            config.username = Some(fixture.username.clone());
            config.identity_file = Some(fixture.private_key_path.clone());

            let session = tokio::time::timeout(
                Duration::from_secs(20),
                run_exec_capture(&config, format!("echo hello from rust {label} to real go")),
            )
            .await
            .unwrap()
            .unwrap();

            assert_eq!(session.exit_status, 0, "{label}: {session:?}");
            assert_eq!(
                session.stdout,
                format!("hello from rust {label} to real go\n").into_bytes(),
                "{label}: {session:?}"
            );
            assert!(session.stderr.is_empty(), "{label}: {session:?}");
            assert!(
                session
                    .server_header
                    .as_deref()
                    .is_some_and(|value| value.starts_with("SSH ")),
                "{label}: {session:?}"
            );

            let _ = server.kill().await;
            let _ = server.wait().await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_exec_round_trips_with_oidc_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_oidc_fixture().await;
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh3")).unwrap();
        fs::write(
            home_dir.join(".ssh3").join("authorized_identities"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let mut server = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.oidc = Some(OidcConfig {
            issuer_url: fixture.issuer_url.clone(),
            client_id: fixture.client_id.clone(),
            client_secret: None,
            use_pkce: true,
        });

        let session = tokio::time::timeout(
            Duration::from_secs(20),
            run_exec_capture_with_browser_opener(
                &config,
                "echo hello from rust oidc to real go",
                mock_browser_opener,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(session.exit_status, 0, "{session:?}");
        assert_eq!(
            session.stdout,
            b"hello from rust oidc to real go\n".to_vec()
        );
        assert!(session.stderr.is_empty(), "{session:?}");
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH ")),
            "{session:?}"
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_ed25519_bearer_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.identity_file = Some(private_key_path);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated client\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated client\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_nist_p256_bearer_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::NistP256);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.identity_file = Some(private_key_path);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via p256\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via p256\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_rsa_bearer_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Rsa);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.identity_file = Some(private_key_path);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via rsa\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via rsa\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_client_exec_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let output = run_go_interop_client(
            &format!("https://localhost:{}/ssh3-term", server_addr.port()),
            &username,
            &private_key_path,
            "printf 'hello from go to rust\\n'",
        )
        .await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"hello from go to rust\n".to_vec());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("go interop client failed"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_exec_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let output = run_go_cli_client(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            &["echo", "hello from real go cli"],
        )
        .await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert_eq!(stdout, "hello from real go cli\n");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_exec_round_trips_with_oidc_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_oidc_fixture().await;
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let issuer_url = fixture.issuer_url.clone();
        let client_id = fixture.client_id.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let oidc_config_path = tempdir.path().join("oidc_config.json");
        fs::write(
            &oidc_config_path,
            format!(
                r#"[{{"issuer_url":"{issuer_url}","client_id":"{client_id}","client_secret":""}}]"#
            ),
        )
        .unwrap();

        let output = run_go_cli_client_with_oidc(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &issuer_url,
            &oidc_config_path,
            &["echo", "hello from real go oidc"],
        )
        .await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert_eq!(stdout, "hello from real go oidc\n");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not get token"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_exec_round_trips_with_password_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let username = current_username();
        let password = "correct horse battery staple".to_string();
        let expected_username = username.clone();
        let expected_password = password.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.enable_password_login = true;
            config.password_verifier =
                Some(Arc::new(move |candidate_username, candidate_password| {
                    Ok(candidate_username == expected_username
                        && candidate_password == expected_password)
                }));
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let output = run_go_cli_client_with_password(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &password,
            &["echo", "hello from real go password"],
        )
        .await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(stdout.contains("hello from real go password\n"), "{stdout}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not get password"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_shell_with_pty_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let mut server = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let client = connect_client(&config).await.unwrap();
        let session = timeout(
            Duration::from_secs(20),
            run_shell_capture_with_resize_on_client(
                &client,
                LocalTerminalInfo {
                    term: Some("xterm-256color".to_string()),
                    size: TerminalSize {
                        char_width: 80,
                        char_height: 24,
                        pixel_width: 640,
                        pixel_height: 480,
                    },
                },
                TerminalSize {
                    char_width: 100,
                    char_height: 40,
                    pixel_width: 800,
                    pixel_height: 600,
                },
                "stty size\n",
                "stty size\nprintf '__SSH3_PTY_RUST_CLIENT_OK__:%s\\n' \"$TERM\"\nexit\n",
            ),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(session.exit_status, 0, "{session:?}");
        let stdout = String::from_utf8_lossy(&session.stdout);
        assert!(stdout.contains("24 80"), "{stdout}");
        assert!(stdout.contains("40 100"), "{stdout}");
        assert!(
            stdout.contains("__SSH3_PTY_RUST_CLIENT_OK__:xterm-256color"),
            "{stdout}"
        );
        assert!(
            session
                .server_header
                .as_deref()
                .is_some_and(|value| value.starts_with("SSH ")),
            "{session:?}"
        );

        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_shell_with_pty_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let output = run_go_cli_shell(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            "printf '__SSH3_PTY_GO_CLIENT_OK__:%s\\n' \"$TERM\"\nexit\n",
        )
        .await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(
            stdout.contains("__SSH3_PTY_GO_CLIENT_OK__:xterm"),
            "{stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_window_change_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let session = spawn_go_cli_shell_with_pty(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            TerminalSize {
                char_width: 80,
                char_height: 24,
                pixel_width: 640,
                pixel_height: 480,
            },
        )
        .await;
        session.write_all("stty size\n").await;
        session.wait_for_output_fragment("24 80").await;
        session
            .resize(TerminalSize {
                char_width: 100,
                char_height: 40,
                pixel_width: 800,
                pixel_height: 600,
            })
            .unwrap();
        session
            .write_all("stty size\nprintf '__SSH3_GO_CLIENT_RESIZE_OK__\\n'\nexit\n")
            .await;
        let output = session.wait_with_output().await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(stdout.contains("24 80"), "{stdout}");
        assert!(stdout.contains("40 100"), "{stdout}");
        assert!(stdout.contains("__SSH3_GO_CLIENT_RESIZE_OK__"), "{stdout}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_signal_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let session = spawn_go_cli_shell_with_pty(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            TerminalSize {
                char_width: 80,
                char_height: 24,
                pixel_width: 640,
                pixel_height: 480,
            },
        )
        .await;
        session.write_all("stty size\n").await;
        session.wait_for_output_fragment("24 80").await;
        session
            .write_all(
                "trap 'printf __SSH3_GO_CLIENT_SIGNAL_OK__\\\\n; exit 0' TERM\nprintf '__SSH3_SIGNAL_ARMED__:%s\\n' \"$TERM\"\nwhile :; do sleep 1; done\n",
            )
            .await;
        session
            .wait_for_output_fragment("__SSH3_SIGNAL_ARMED__:xterm")
            .await;
        session.send_signal(nix::libc::SIGTERM).unwrap();
        let output = session.wait_with_output().await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).replace('\r', "");
        assert!(stdout.contains("__SSH3_GO_CLIENT_SIGNAL_OK__"), "{stdout}");

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_tcp_forwarding_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");
        let (remote_addr, echo_task) = spawn_tcp_echo_server().await;

        let mut server = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let client = connect_client(&config).await.unwrap();
        let payload = b"tcp forward rust to real go";
        let echoed = timeout(
            Duration::from_secs(20),
            run_tcp_forwarding_round_trip_on_client(&client, remote_addr, payload),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(echoed, payload.to_vec());

        echo_task.abort();
        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_tcp_forwarding_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let (remote_addr, echo_task) = spawn_tcp_echo_server().await;

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let local_port = reserve_tcp_port();
        let log_path = tempdir.path().join("go-client-forward.log");
        let mut forwarder = spawn_go_cli_tcp_forwarder(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            local_port,
            remote_addr,
            &log_path,
        )
        .await;

        let mut stream = TcpStream::connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            local_port,
        )))
        .await
        .unwrap();
        let payload = b"tcp forward real go to rust";
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        let status = timeout(Duration::from_secs(15), forwarder.wait())
            .await
            .unwrap()
            .unwrap();
        let logs = fs::read_to_string(&log_path).unwrap_or_default();
        assert_eq!(status.code(), Some(0), "logs:\n{logs}");
        assert!(!logs.contains("could not forward"), "{logs}");
        assert!(!logs.contains("could not dial"), "{logs}");
        assert!(!logs.contains("an error was encountered"), "{logs}");

        echo_task.abort();
        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_udp_forwarding_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");
        let (remote_addr, echo_task) = spawn_udp_echo_server().await;

        let mut server = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());

        let client = connect_client(&config).await.unwrap();
        let payload = b"udp forward rust to real go";
        let echoed = timeout(
            Duration::from_secs(20),
            run_udp_forwarding_round_trip_on_client(&client, remote_addr, payload),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(echoed, payload.to_vec());

        echo_task.abort();
        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_udp_forwarding_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let (remote_addr, echo_task) = spawn_udp_echo_server().await;

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let local_port = reserve_udp_port();
        let log_path = tempdir.path().join("go-client-forward.log");
        let mut forwarder = spawn_go_cli_udp_forwarder(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            local_port,
            remote_addr,
            &log_path,
        )
        .await;

        let socket =
            TokioUdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
        let forward_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_port));
        let payload = b"udp forward real go to rust";
        socket.send_to(payload, forward_addr).await.unwrap();

        let mut echoed = vec![0; 1024];
        let (n, source) = timeout(Duration::from_secs(10), socket.recv_from(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, forward_addr);
        assert_eq!(&echoed[..n], payload);

        let status = timeout(Duration::from_secs(15), forwarder.wait())
            .await
            .unwrap()
            .unwrap();
        let logs = fs::read_to_string(&log_path).unwrap_or_default();
        assert_eq!(status.code(), Some(0), "logs:\n{logs}");
        assert!(!logs.contains("could not forward"), "{logs}");
        assert!(!logs.contains("could not dial"), "{logs}");
        assert!(!logs.contains("an error was encountered"), "{logs}");

        echo_task.abort();
        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_capture_round_trips_with_ed25519_agent_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key = ssh3_auth::load_private_key(&fixture.private_key_path).unwrap();
        let agent = spawn_mock_agent(private_key).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.agent = Some(super::AgentSelection::First);
        config.agent_socket = Some(agent.socket_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via agent\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via agent\n".to_vec(),
                stderr: Vec::new(),
            }
        );
        assert_eq!(agent.sign_flags(), vec![0]);

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_capture_round_trips_with_rsa_agent_auth() {
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Rsa);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let private_key = ssh3_auth::load_private_key(&private_key_path).unwrap();
        let agent = spawn_mock_agent(private_key).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.agent = Some(super::AgentSelection::PublicKey(private_key_path));
        config.agent_socket = Some(agent.socket_path.clone());

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via rsa agent\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via rsa agent\n".to_vec(),
                stderr: Vec::new(),
            }
        );
        assert_eq!(agent.sign_flags(), vec![SSH_AGENT_RSA_SHA2_256]);

        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn forward_agent_exposes_remote_ssh_auth_sock_and_proxies_requests() {
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, ServerConfig::default()),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.forward_agent = true;
        config.agent_socket = Some(agent.socket_path.clone());

        let client = connect_client(&config).await.unwrap();
        let channel = client.open_session_channel().await.unwrap();
        let request =
            SessionRequest::Exec("printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 2".to_string());
        send_forward_agent_request(channel.as_ref()).await.unwrap();
        let session_runtime =
            build_session_runtime(&client, &config, channel.clone(), &request, None).unwrap();
        send_initial_session_requests(channel.as_ref(), &request, None)
            .await
            .unwrap();

        let socket_path = tokio::time::timeout(Duration::from_secs(5), read_stdout_line(&channel))
            .await
            .unwrap()
            .unwrap();
        assert!(!socket_path.is_empty());

        let signature = request_forwarded_agent_signature(&socket_path, b"forwarded agent")
            .await
            .unwrap();
        assert!(!signature.is_empty());
        assert_eq!(agent.sign_flags(), vec![0]);

        loop {
            match channel.next_message().await.unwrap() {
                Message::ChannelRequest(message) => match message.request {
                    ChannelRequest::ExitStatus(status) => {
                        assert_eq!(status.exit_status, 0);
                        break;
                    }
                    ChannelRequest::ExitSignal(signal) => {
                        panic!("unexpected exit signal: {signal:?}")
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        drop(session_runtime);
        client.shutdown().await;
        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn forward_agent_survives_multiple_remote_connections_in_one_session() {
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, ServerConfig::default()),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.forward_agent = true;
        config.agent_socket = Some(agent.socket_path.clone());

        let client = connect_client(&config).await.unwrap();
        let channel = client.open_session_channel().await.unwrap();
        let request =
            SessionRequest::Exec("printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 3".to_string());
        send_forward_agent_request(channel.as_ref()).await.unwrap();
        let session_runtime =
            build_session_runtime(&client, &config, channel.clone(), &request, None).unwrap();
        send_initial_session_requests(channel.as_ref(), &request, None)
            .await
            .unwrap();

        let socket_path = tokio::time::timeout(Duration::from_secs(5), read_stdout_line(&channel))
            .await
            .unwrap()
            .unwrap();
        assert!(!socket_path.is_empty());

        let first_signature =
            request_forwarded_agent_signature(&socket_path, b"forwarded agent one")
                .await
                .unwrap();
        let second_signature =
            request_forwarded_agent_signature(&socket_path, b"forwarded agent two")
                .await
                .unwrap();
        assert!(!first_signature.is_empty());
        assert!(!second_signature.is_empty());
        assert_ne!(first_signature, second_signature);
        assert_eq!(agent.sign_flags(), vec![0, 0]);

        loop {
            match channel.next_message().await.unwrap() {
                Message::ChannelRequest(message) => match message.request {
                    ChannelRequest::ExitStatus(status) => {
                        assert_eq!(status.exit_status, 0);
                        break;
                    }
                    ChannelRequest::ExitSignal(signal) => {
                        panic!("unexpected exit signal: {signal:?}")
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        drop(session_runtime);
        client.shutdown().await;
        server_task.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rust_client_forward_agent_round_trips_against_the_real_go_server() {
        let _guard = lock_go_binary_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let tempdir = TempDir::new().unwrap();
        let home_dir = tempdir.path().join("home");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::write(
            home_dir.join(".ssh").join("authorized_keys"),
            fs::read(&fixture.authorized_identities_path).unwrap(),
        )
        .unwrap();

        let bind_port = reserve_udp_port();
        let bind_addr = format!("127.0.0.1:{bind_port}");
        let cert_path = tempdir.path().join("cert.pem");
        let key_path = tempdir.path().join("key.pem");
        let log_path = tempdir.path().join("go-server.log");

        let mut server = spawn_go_cli_server(
            &bind_addr,
            &fixture.username,
            &home_dir,
            &cert_path,
            &key_path,
            &log_path,
        )
        .await;

        let mut config = ClientConfig::new(
            format!(
                "https://127.0.0.1:{bind_port}/ssh3-term?user={}",
                fixture.username
            )
            .parse()
            .unwrap(),
        );
        config.trust = TrustStrategy::Insecure;
        config.username = Some(fixture.username.clone());
        config.identity_file = Some(fixture.private_key_path.clone());
        config.forward_agent = true;
        config.agent_socket = Some(agent.socket_path.clone());

        let client = connect_client(&config).await.unwrap();
        let channel = client.open_session_channel().await.unwrap();
        let request =
            SessionRequest::Exec("printf '%s\\n' \"$SSH_AUTH_SOCK\"; sleep 2".to_string());
        send_forward_agent_request(channel.as_ref()).await.unwrap();
        let session_runtime =
            build_session_runtime(&client, &config, channel.clone(), &request, None).unwrap();
        send_initial_session_requests(channel.as_ref(), &request, None)
            .await
            .unwrap();

        let socket_path = match timeout(Duration::from_secs(5), read_stdout_line(&channel)).await {
            Ok(Ok(path)) => path,
            Ok(Err(err)) => {
                let logs = fs::read_to_string(&log_path).unwrap_or_default();
                panic!(
                    "failed to read forwarded SSH_AUTH_SOCK from real Go server: {err}\nlogs:\n{logs}"
                );
            }
            Err(_) => {
                let logs = fs::read_to_string(&log_path).unwrap_or_default();
                panic!(
                    "timed out reading forwarded SSH_AUTH_SOCK from real Go server\nlogs:\n{logs}"
                );
            }
        };
        assert!(!socket_path.is_empty());

        let signature =
            request_forwarded_agent_signature(&socket_path, b"real go server forwarded agent")
                .await
                .unwrap();
        assert!(!signature.is_empty());
        assert_eq!(agent.sign_flags(), vec![0]);

        loop {
            match channel.next_message().await.unwrap() {
                Message::ChannelRequest(message) => match message.request {
                    ChannelRequest::ExitStatus(status) => {
                        assert_eq!(status.exit_status, 0);
                        break;
                    }
                    ChannelRequest::ExitSignal(signal) => {
                        panic!("unexpected exit signal: {signal:?}")
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        drop(session_runtime);
        client.shutdown().await;
        let _ = server.kill().await;
        let _ = server.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn go_agent_probe_talks_to_mock_agent_locally() {
        let _guard = lock_go_binary_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let probe = go_agent_probe_binary();

        let output = timeout(
            Duration::from_secs(10),
            TokioCommand::new(&probe.path)
                .env("SSH_AUTH_SOCK", agent.socket_path.as_path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("SSH3_AGENT_PROBE_OK 1 ssh-ed25519"),
            "{stdout}"
        );
        assert_eq!(agent.sign_flags(), vec![0]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_go_client_forward_agent_round_trips_against_the_rust_server() {
        let _guard = lock_go_binary_tests();
        let agent = spawn_mock_agent(auth_private_key(AuthKeyAlgorithm::Ed25519)).await;
        let probe = go_agent_probe_binary();
        let fixture = create_auth_fixture(AuthKeyAlgorithm::Ed25519);
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let private_key_path = fixture.private_key_path.clone();
        let (server_config, _server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            serve_connection(connection, config).await.unwrap();
        });

        let tempdir = TempDir::new().unwrap();
        let output = run_go_cli_client_with_forwarded_agent(
            tempdir.path(),
            &format!("{}@localhost:{}/ssh3-term", username, server_addr.port()),
            &private_key_path,
            agent.socket_path.as_path(),
            &[probe.path.to_string_lossy().as_ref()],
        )
        .await;

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("SSH3_AGENT_PROBE_OK 1 ssh-ed25519"),
            "{stdout}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("agent forwarding error"), "{output:?}");
        assert!(!stderr.contains("could not establish"), "{output:?}");
        assert!(!stderr.contains("an error was encountered"), "{output:?}");
        assert_eq!(agent.sign_flags(), vec![0]);

        if server_task.is_finished() {
            server_task.await.unwrap();
        } else {
            server_task.abort();
            let _ = server_task.await;
        }
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_oidc_bearer_auth() {
        let fixture = create_oidc_fixture().await;
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        let client = connect_client_with_authorization_builder(&config, |conversation_id| {
            bearer_authorization_value(
                &fixture.bearer_token_for_nonce(&conversation_id_base64(conversation_id)),
            )
        })
        .await
        .unwrap();
        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_capture_on_client(
                &client,
                &config,
                SessionRequest::Exec("printf 'authenticated via oidc\\n'".to_string()),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        client.shutdown().await;

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via oidc\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_interactive_oidc_login() {
        let fixture = create_oidc_fixture().await;
        let authorized_identities_path = fixture.authorized_identities_path.clone();
        let username = fixture.username.clone();
        let issuer_url = fixture.issuer_url.clone();
        let client_id = fixture.client_id.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.require_authentication = true;
            config.authorized_identity_paths = vec![authorized_identities_path.clone()];
            config.default_user = Some("does-not-exist".to_string());
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.oidc = Some(OidcConfig {
            issuer_url,
            client_id,
            client_secret: None,
            use_pkce: true,
        });

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture_with_browser_opener(
                &config,
                "printf 'authenticated via oidc login\\n'",
                mock_browser_opener,
            ),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via oidc login\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exec_capture_round_trips_with_basic_password_auth() {
        let username = {
            #[cfg(unix)]
            {
                current_username()
            }
            #[cfg(not(unix))]
            {
                "user".to_string()
            }
        };
        let password = "correct horse battery staple".to_string();
        let expected_username = username.clone();
        let expected_password = password.clone();
        let (server_config, server_certificate) =
            self_signed_server_config(vec!["localhost".to_string()]).unwrap();
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = tokio::time::timeout(Duration::from_secs(5), server_endpoint.accept())
                .await
                .unwrap()
                .unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(5), incoming)
                .await
                .unwrap()
                .unwrap();
            let mut config = ServerConfig::default();
            config.enable_password_login = true;
            config.default_user = Some("does-not-exist".to_string());
            config.password_verifier =
                Some(Arc::new(move |candidate_username, candidate_password| {
                    Ok(candidate_username == expected_username
                        && candidate_password == expected_password)
                }));
            tokio::time::timeout(
                Duration::from_secs(10),
                serve_connection(connection, config),
            )
            .await
            .unwrap()
            .unwrap();
        });

        let mut config = ClientConfig::new(
            format!("https://localhost:{}/ssh3-term", server_addr.port())
                .parse()
                .unwrap(),
        );
        config.trust = TrustStrategy::Certificates(vec![server_certificate]);
        config.username = Some(username);
        config.password = Some(password);

        let session = tokio::time::timeout(
            Duration::from_secs(10),
            run_exec_capture(&config, "printf 'authenticated via password\\n'"),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(
            session,
            CapturedSession {
                server_header: Some(SSH3_VERSION_STRING.to_string()),
                exit_status: 0,
                stdout: b"authenticated via password\n".to_vec(),
                stderr: Vec::new(),
            }
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn shell_requests_send_pty_before_shell_when_terminal_metadata_is_available() {
        let (client, server_task) = setup_request_capture_harness(2).await;
        let channel = client.open_session_channel().await.unwrap();
        send_initial_session_requests(
            channel.as_ref(),
            &SessionRequest::Shell,
            Some(&LocalTerminalInfo {
                term: Some("xterm-256color".to_string()),
                size: TerminalSize {
                    char_width: 80,
                    char_height: 24,
                    pixel_width: 640,
                    pixel_height: 480,
                },
            }),
        )
        .await
        .unwrap();

        let messages = server_task.await.unwrap();
        match &messages[0] {
            Message::ChannelRequest(message) => match &message.request {
                ChannelRequest::Pty(request) => {
                    assert_eq!(request.term, b"xterm-256color".to_vec());
                    assert_eq!(request.char_width, 80);
                    assert_eq!(request.char_height, 24);
                    assert_eq!(request.pixel_width, 640);
                    assert_eq!(request.pixel_height, 480);
                }
                other => panic!("expected pty request, got {other:?}"),
            },
            other => panic!("expected channel request, got {other:?}"),
        }
        match &messages[1] {
            Message::ChannelRequest(message) => {
                assert!(matches!(message.request, ChannelRequest::Shell));
            }
            other => panic!("expected channel request, got {other:?}"),
        }

        client.shutdown().await;
    }

    #[tokio::test]
    async fn window_change_helper_sends_resize_request() {
        let (client, server_task) = setup_request_capture_harness(1).await;
        let channel = client.open_session_channel().await.unwrap();
        send_window_change_request(
            channel.as_ref(),
            TerminalSize {
                char_width: 101,
                char_height: 33,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
        .await
        .unwrap();

        let messages = server_task.await.unwrap();
        match &messages[0] {
            Message::ChannelRequest(message) => match &message.request {
                ChannelRequest::WindowChange(request) => {
                    assert_eq!(request.char_width, 101);
                    assert_eq!(request.char_height, 33);
                }
                other => panic!("expected window-change request, got {other:?}"),
            },
            other => panic!("expected channel request, got {other:?}"),
        }

        client.shutdown().await;
    }

    #[tokio::test]
    async fn signal_helper_sends_signal_request() {
        let (client, server_task) = setup_request_capture_harness(1).await;
        let channel = client.open_session_channel().await.unwrap();
        send_signal_request(channel.as_ref(), "TERM").await.unwrap();

        let messages = server_task.await.unwrap();
        match &messages[0] {
            Message::ChannelRequest(message) => match &message.request {
                ChannelRequest::Signal(request) => {
                    assert_eq!(request.signal_name_without_sig, b"TERM".to_vec());
                }
                other => panic!("expected signal request, got {other:?}"),
            },
            other => panic!("expected channel request, got {other:?}"),
        }

        client.shutdown().await;
    }
}
