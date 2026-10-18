use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{ArgGroup, CommandFactory, Parser, ValueHint, error::ErrorKind};
use http::Uri;
use ssh3_client::{
    AgentSelection, ClientConfig, OidcConfig, SessionRequest, TrustStrategy, load_certificates,
    run_session_stdio,
};

#[derive(Debug, Parser)]
#[command(
    name = "ssh3-client",
    version,
    about = "Connects to an SSH3 server over QUIC/HTTP3. If COMMAND is omitted, requests a shell.",
    group(
        ArgGroup::new("auth")
            .args([
                "identity",
                "agent",
                "agent_key",
                "password",
                "password_file",
                "bearer_token",
                "bearer_token_file",
                "oidc_issuer_url",
            ])
            .multiple(false)
    )
)]
struct Cli {
    #[arg(long, value_name = "NAME")]
    server_name: Option<String>,

    #[arg(long, value_name = "NAME")]
    user: Option<String>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    identity: Option<PathBuf>,

    #[arg(long, requires = "user", conflicts_with = "agent_key")]
    agent: bool,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires = "user",
        conflicts_with = "agent"
    )]
    agent_key: Option<PathBuf>,

    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    agent_socket: Option<PathBuf>,

    #[arg(long)]
    forward_agent: bool,

    #[arg(
        long,
        value_name = "PASS",
        requires = "user",
        conflicts_with = "password_file",
        help = "Password for basic authentication. Prefer --password-file to avoid exposing secrets in argv."
    )]
    password: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires = "user",
        conflicts_with = "password",
        help = "Read the basic-auth password from a file."
    )]
    password_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with = "bearer_token_file",
        help = "Bearer token to send in Authorization. Prefer --bearer-token-file to avoid exposing secrets in argv."
    )]
    bearer_token: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        conflicts_with = "bearer_token",
        help = "Read the bearer token from a file."
    )]
    bearer_token_file: Option<PathBuf>,

    #[arg(long = "use-oidc", value_name = "ISSUER", requires = "oidc_client_id")]
    oidc_issuer_url: Option<String>,

    #[arg(long, value_name = "ID", requires = "oidc_issuer_url")]
    oidc_client_id: Option<String>,

    #[arg(
        long,
        value_name = "SECRET",
        requires_all = ["oidc_issuer_url", "oidc_client_id"],
        conflicts_with = "oidc_client_secret_file",
        help = "OIDC client secret. Prefer --oidc-client-secret-file to avoid exposing secrets in argv."
    )]
    oidc_client_secret: Option<String>,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        requires_all = ["oidc_issuer_url", "oidc_client_id"],
        conflicts_with = "oidc_client_secret",
        help = "Read the OIDC client secret from a file."
    )]
    oidc_client_secret_file: Option<PathBuf>,

    #[arg(long)]
    no_pkce: bool,

    #[arg(
        long,
        value_name = "PATH",
        value_hint = ValueHint::FilePath,
        conflicts_with = "insecure"
    )]
    ca_cert: Option<PathBuf>,

    #[arg(long, conflicts_with = "ca_cert")]
    insecure: bool,

    #[arg(value_name = "URL")]
    url: Uri,

    #[arg(value_name = "COMMAND", trailing_var_arg = true, num_args = 0..)]
    command: Vec<String>,
}

fn cli_error(kind: ErrorKind, message: impl Into<String>) -> clap::Error {
    Cli::command().error(kind, message.into())
}

fn read_secret_file(path: &Path, label: &str) -> Result<String, clap::Error> {
    std::fs::read_to_string(path)
        .map(|contents| contents.trim_end_matches(['\r', '\n']).to_string())
        .map_err(|err| cli_error(ErrorKind::Io, format!("failed to read {label}: {err}")))
}

fn build_config(cli: Cli) -> Result<(ClientConfig, SessionRequest), clap::Error> {
    let mut config = ClientConfig::new(cli.url);
    config.server_name = cli.server_name;
    config.username = cli.user;
    config.identity_file = cli.identity;
    config.agent = if cli.agent {
        Some(AgentSelection::First)
    } else {
        cli.agent_key.map(AgentSelection::PublicKey)
    };
    config.agent_socket = cli.agent_socket;
    config.forward_agent = cli.forward_agent;
    config.password = match (cli.password, cli.password_file) {
        (Some(password), None) => Some(password),
        (None, Some(path)) => Some(read_secret_file(&path, "password file")?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces password conflicts"),
    };
    config.bearer_token = match (cli.bearer_token, cli.bearer_token_file) {
        (Some(token), None) => Some(token.trim().to_string()),
        (None, Some(path)) => Some(read_secret_file(&path, "bearer token file")?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces bearer token conflicts"),
    };
    config.oidc = match (cli.oidc_issuer_url, cli.oidc_client_id) {
        (Some(issuer_url), Some(client_id)) => Some(OidcConfig {
            issuer_url,
            client_id,
            client_secret: match (cli.oidc_client_secret, cli.oidc_client_secret_file) {
                (Some(secret), None) => Some(secret),
                (None, Some(path)) => Some(read_secret_file(&path, "OIDC client secret file")?),
                (None, None) => None,
                (Some(_), Some(_)) => unreachable!("clap enforces OIDC secret conflicts"),
            },
            use_pkce: !cli.no_pkce,
        }),
        (None, None) => None,
        (Some(_), None) | (None, Some(_)) => unreachable!("clap enforces OIDC requirements"),
    };
    config.trust = if cli.insecure {
        TrustStrategy::Insecure
    } else if let Some(path) = cli.ca_cert {
        TrustStrategy::Certificates(load_certificates(&path).map_err(|err| {
            cli_error(
                ErrorKind::ValueValidation,
                format!("failed to load CA certificate: {err}"),
            )
        })?)
    } else {
        TrustStrategy::WebPkiRoots
    };

    let request = if cli.command.is_empty() {
        SessionRequest::Shell
    } else {
        SessionRequest::Exec(cli.command.join(" "))
    };
    Ok((config, request))
}

fn parse_args() -> Result<(ClientConfig, SessionRequest), clap::Error> {
    build_config(Cli::try_parse()?)
}

#[tokio::main]
async fn main() -> ExitCode {
    let (config, request) = match parse_args() {
        Ok(parsed) => parsed,
        Err(err) => {
            let status = match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::FAILURE,
            };
            err.print().ok();
            return status;
        }
    };

    match run_session_stdio(&config, request).await {
        Ok(status) => ExitCode::from(status as u8),
        Err(err) => {
            eprintln!("ssh3-client failed: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, build_config};
    use clap::{Parser, error::ErrorKind};

    #[test]
    fn password_file_is_loaded_and_trimmed() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let password_file = tempdir.path().join("password.txt");
        std::fs::write(&password_file, "secret-password\n").unwrap();

        let cli = Cli::try_parse_from([
            "ssh3-client",
            "--user",
            "alice",
            "--password-file",
            password_file.to_str().unwrap(),
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let (config, _) = build_config(cli).unwrap();

        assert_eq!(config.password.as_deref(), Some("secret-password"));
    }

    #[test]
    fn oidc_client_secret_file_is_loaded_and_trimmed() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let secret_file = tempdir.path().join("oidc-secret.txt");
        std::fs::write(&secret_file, "client-secret\r\n").unwrap();

        let cli = Cli::try_parse_from([
            "ssh3-client",
            "--use-oidc",
            "https://issuer.example",
            "--oidc-client-id",
            "client-id",
            "--oidc-client-secret-file",
            secret_file.to_str().unwrap(),
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap();
        let (config, _) = build_config(cli).unwrap();

        assert_eq!(
            config
                .oidc
                .as_ref()
                .and_then(|oidc| oidc.client_secret.as_deref()),
            Some("client-secret")
        );
    }

    #[test]
    fn clap_rejects_multiple_auth_methods() {
        let err = Cli::try_parse_from([
            "ssh3-client",
            "--identity",
            "/tmp/id",
            "--bearer-token-file",
            "/tmp/token",
            "https://localhost:4433/ssh3-term",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }
}
