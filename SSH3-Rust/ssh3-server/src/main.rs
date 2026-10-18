use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueHint, error::ErrorKind};
use ssh3_server::{ServerConfig, run_with_self_signed};

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-server",
    version,
    about = "Starts a minimal Rust SSH3 server with a self-signed certificate."
)]
struct Cli {
    #[arg(long, value_name = "ADDR")]
    bind: Option<SocketAddr>,

    #[arg(long, value_name = "NAME", action = clap::ArgAction::Append)]
    hostname: Vec<String>,

    #[arg(long = "server-header", value_name = "TEXT")]
    server_header: Option<String>,

    #[arg(long)]
    require_auth: bool,

    #[arg(long)]
    enable_password_login: bool,

    #[arg(
        long = "authorized-identity",
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        action = clap::ArgAction::Append
    )]
    authorized_identity: Vec<PathBuf>,

    #[arg(long, value_name = "NAME")]
    user: Option<String>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    shell: Option<String>,
}

fn parse_args() -> Result<ServerConfig, clap::Error> {
    let cli = Cli::try_parse()?;
    let mut config = ServerConfig::default();
    if let Some(bind_addr) = cli.bind {
        config.bind_addr = bind_addr;
    }
    if !cli.hostname.is_empty() {
        config.cert_subject_alt_names = cli.hostname;
    }
    if let Some(server_header) = cli.server_header {
        config.server_header = server_header;
    }
    config.require_authentication = cli.require_auth;
    config.enable_password_login = cli.enable_password_login;
    if !cli.authorized_identity.is_empty() {
        config.authorized_identity_paths = cli.authorized_identity;
    }
    if let Some(user) = cli.user {
        config.default_user = Some(user);
    }
    if let Some(shell) = cli.shell {
        config.shell = Some(shell);
    }
    Ok(config)
}

#[tokio::main]
async fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(config) => config,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
            err.print().ok();
            return status;
        }
    };

    match run_with_self_signed(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ssh3-server failed: {err}");
            ExitCode::FAILURE
        }
    }
}
