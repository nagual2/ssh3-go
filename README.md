<div align="center">
<img src="resources/figures/ssh3.png" style="display: block; width: 60%">
</div>

> [!NOTE]
> SSH3 is still experimental, and the protocol name may still change. The protocol remains SSH-style session and channel semantics carried over QUIC and HTTP/3 Extended CONNECT, but the implementation and surrounding product surface are still evolving.

# SSH3 over HTTP/3
**English** | [Русский](README.ru.md) | [Deutsch](README.de.md)

SSH3 maps RFC 4254-style remote session semantics onto QUIC, TLS 1.3, and HTTP/3 Extended CONNECT. The project aims to preserve familiar SSH workflows while adding HTTP-native authentication and QUIC-native transport features such as datagram forwarding.

This repository currently contains two implementations:

- The original Go client and server in [`cmd/ssh3`](cmd/ssh3) and [`cmd/ssh3-server`](cmd/ssh3-server)
- An in-progress Rust rewrite in [`crates/`](crates)

> [!WARNING]
> Do not treat either implementation as production-hardened. The protocol and code are still under active development, and the Rust rewrite is focused on correctness and interoperability first, not product completeness.

## About the nagual2 fork
This fork focuses on making the Go implementation a practical daily driver. This README is adapted from the upstream project's README and modified by the fork maintainers; fork-only changes are tracked in [CHANGELOG.md](CHANGELOG.md):

- **Windows client is a first-class citizen.** Since v0.1.8 the client compiles for Windows and supports interactive PTY sessions: VT input/output, UTF-8 console code page, real console size, `SIGINT`/`SIGTERM` forwarding, and a 80x24 PTY fallback when the console size cannot be queried.
- **Server packaging: keys by default, passwords opt-in.** The release `.deb` ships a systemd service (`ssh3-server.service`, UDP 443, secret URL path); no OIDC is configured, and the post-install script generates a self-signed ed25519 certificate with IP/DNS SANs. On amd64 builds the password backend is compiled in and enabled by default (`SSH3_ENABLE_PASSWORD_LOGIN=0` turns it off); arm server builds are key-only.
- **OpenSSH-parity systemd unit.** The unit ships no sandbox directives (`CapabilityBoundingSet`, `NoNewPrivileges`, `Protect*`): the root daemon spawns every session with the authenticated user's uid/gid (like sshd), so `sudo` inside a session regains full root capabilities — tcpdump, trafshow, modprobe and sysctl all work. `KillMode=process` keeps active sessions alive across daemon restarts, as in Debian's `ssh.service`. The trust boundary is key-only auth, not unit-level sandboxing.
- **Login stats banner.** Interactive sessions print uptime, load, memory, and disk statistics before the shell prompt (`exec` requests are not affected).
- **Locale and shell fixes.** The server forwards `LANG`/`LC_*` from its systemd environment to user shells and starts the account's real login shell from `/etc/passwd` instead of a hardcoded `/bin/sh`.
- **CI.** Every `v*` tag produces release archives and a `.deb` via goreleaser; every push to `main` produces Windows client artifacts.

## Download & Install
Grab the assets from the [latest release](https://github.com/nagual2/ssh3-go/releases/latest):

| File | Purpose |
| --- | --- |
| `ssh3-go_client_<ver>_windows_amd64.zip` | Windows client (`ssh3.exe`) |
| `ssh3-go_client_<ver>_<os>_<arch>.tar.gz` | Client for Linux, macOS, FreeBSD, OpenBSD |
| `ssh3-go_server_<ver>_linux_<arch>.tar.gz` | Linux server binaries |
| `ssh3-go_<ver>_amd64.deb` | Server + client package for Debian/Ubuntu/Mint (systemd service, password auth on by default on amd64 (`SSH3_ENABLE_PASSWORD_LOGIN=0` disables)) |

Install the Debian package:

```bash
sudo dpkg -i ssh3-go_0.1.26_amd64.deb
```

The `ssh3-go` package replaces the previous `ssh3` package in place (Conflicts/Replaces); binaries (`ssh3`, `ssh3-server`) and the `ssh3-server.service` unit keep their names.

The service listens on UDP 443 under the secret URL path `/ssh3-term`. Configuration lives in `/etc/ssh3/ssh3-server.env` (log file and level, `LANG`), the systemd unit in `/usr/lib/systemd/system/ssh3-server.service`, and a self-signed ed25519 certificate with IP/DNS SANs is generated in `/etc/ssh3/` on install if missing.

### Server configuration
The release package is configured through the systemd `EnvironmentFile` at `/etc/ssh3/ssh3-server.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SSH3_LOG_FILE` | `/var/log/ssh3.log` | Server log file |
| `SSH3_LOG_LEVEL` | `info` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`) |
| `SSH3_GATEWAY_PORTS` | `no` | GatewayPorts policy for reverse (-R) forwarding: `no` forces client-requested non-loopback binds back to the loopback, `clientspecified` honors the requested bind address, `yes` binds the wildcard |
| `SSH3_MAX_REVERSE_FORWARDS` | `10` | Maximum active reverse (-R) listeners per user |
| `SSH3_MAX_UNAUTH_CONVERSATIONS` | `100` | Maximum conversations sitting unauthenticated before refusals (DoS guard) |
| `SSH3_MAX_PASSWORD_FAILURES` | `10` | Failed password attempts before the account lockout |
| `SSH3_PASSWORD_LOCKOUT_SECONDS` | `60` | Password brute-force lockout duration in seconds |
| `LANG` | `C.UTF-8` | Locale forwarded to user shells |

Apply changes with `sudo systemctl restart ssh3-server`.

Both client and server accept QUIC transport tuning flags for bulk transfers: `-initial-packet-size` (initial QUIC packet size in bytes, default `1350`), `-stream-rx-mb` (per-stream flow-control receive window in MiB, default `8`), and `-conn-rx-mb` (connection-level receive window in MiB, default `16`).

## Interactive escape sequences
An escape character at the start of a line controls the client: `~.` disconnects, `~^Z` suspends the client locally (unix), `~~` sends one literal `~`; an unknown sequence forwards literally. The character is `~` by default and is picked with `-o EscapeChar=<char|none>` or the same keyword in `~/.ssh/config`.

## Windows client notes
- Flags (such as `-privkey`) must come **before** the positional URL: Go's flag parser stops at the first positional argument.
- The console is switched to UTF-8 and VT processing for the session and restored on exit. Use a Unicode-capable font (Consolas, Lucida Console).
- There is no `/dev/tty` on Windows, so the interactive TOFU prompt cannot run: pin the server certificate in `%USERPROFILE%\.ssh3\known_hosts` (`host:port/path x509-certificate <base64 DER>`), or use `-insecure` consciously.
- SSH agent forwarding is unavailable (unix socket only); window resize is not forwarded (no SIGWINCH equivalent).

## Status
The Go implementation is still the broadest end-user CLI surface. The Rust workspace now covers the protocol core, QUIC/HTTP/3 bootstrap, auth, session handling, PTY shells, resize and signal forwarding, forwarding runtimes, and real Rust<->Go interoperability tests.

The Rust side is no longer just a codec experiment. It includes working client and server binaries, but some operational features are still Go-only today.

## Feature Status
| Capability | Go CLI/server | Rust workspace | Notes |
| --- | --- | --- | --- |
| QUIC + HTTP/3 SSH3 transport | Yes | Yes | Rust uses `quinn` plus a patched vendored `h3` crate. |
| Session shell and exec | Yes | Yes | Covered by unit and real-binary interop tests. |
| PTY shell, resize, and signal forwarding | Yes | Yes | Real-binary resize and signal interop are covered in both directions. Windows clients get a PTY with a fixed 80x24 fallback geometry. |
| Public-key auth | Yes | Yes | Ed25519, P-256, and RSA are covered. |
| Password auth | Yes | Yes | Go password auth uses the system shadow backend (CGO). Release server builds compile it in on amd64 and enable it by default; arm builds are key-only. |
| OpenID Connect auth | Yes | Yes | Tokens are now bound to the SSH3 conversation via nonce checking. |
| SSH agent auth | Yes | Yes | |
| SSH agent forwarding | Yes | Yes | Unix sockets only; not available from Windows clients. |
| Direct TCP forwarding | Yes | Yes | Rust runtime supports it; Rust CLI does not yet expose forwarding flags. |
| Direct UDP forwarding | Yes | Yes | Rust runtime supports it; Rust CLI does not yet expose forwarding flags. |
| Reverse TCP/UDP forwarding | Yes | No | `-R`, currently Go-only. |
| Dynamic SOCKS forwarding | Yes | No | `-D`, currently Go-only. |
| Proxy jump | Yes | No | Currently Go-only. |
| Secret URL path / hidden server path | Yes | No | Currently Go-only. |
| Public certificate automation | Yes | No | Go server supports Let's Encrypt flows; Rust server is self-signed only today. |

## Repository Layout
- [`cmd/ssh3`](cmd/ssh3): original Go client binary
- [`cmd/ssh3-server`](cmd/ssh3-server): original Go server binary
- [`crates/ssh3-proto`](crates/ssh3-proto): wire format, messages, and forwarding headers
- [`crates/ssh3-core`](crates/ssh3-core): conversation and channel runtime
- [`crates/ssh3-quinn`](crates/ssh3-quinn): QUIC bindings
- [`crates/ssh3-h3`](crates/ssh3-h3): HTTP/3 bootstrap and CONNECT handling
- [`crates/ssh3-auth`](crates/ssh3-auth): public-key, password-adjacent helpers, and OIDC verification
- [`crates/ssh3-client`](crates/ssh3-client): Rust client library and binary
- [`crates/ssh3-server`](crates/ssh3-server): Rust server library and binary
- [`internal/interop`](internal/interop): Go helpers used by the Rust real-binary interop suite

## Building
### Rust
Use a recent stable Rust toolchain.

```bash
cargo build --workspace
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

Current Rust CLI surfaces:

```text
$ cargo run -p ssh3-client -- --help
Usage: ssh3-client [OPTIONS] <URL> [COMMAND]...

$ cargo run -p ssh3-server -- --help
Usage: ssh3-server [OPTIONS]
```

For the Rust client, prefer file-backed secret flags such as `--password-file`, `--bearer-token-file`, and `--oidc-client-secret-file` over passing secrets directly on the command line. File-backed secrets are less likely to leak through shell history, process listings, and CI logs.

### Go
Use Go 1.21 or newer. The repository carries a complete `vendor/` tree, so
the builds below work as they are:

```bash
CGO_ENABLED=0 go build -o ssh3 ./cmd/ssh3
CGO_ENABLED=0 go build -tags disable_password_auth -o ssh3-server ./cmd/ssh3-server
```

The release client builds and the arm server builds use `CGO_ENABLED=0` with `-tags disable_password_auth`, which removes password authentication from the binary entirely. The amd64 release server is built with CGO and without the tag, so the shadow/crypt backend is compiled in and enabled by default (`SSH3_ENABLE_PASSWORD_LOGIN=0` disables). The release client builds cannot authenticate with passwords. If you want a password-capable client in your own Linux build:

```bash
CGO_ENABLED=1 go build -o ssh3-server ./cmd/ssh3-server
```

## Quickstart
### Local Rust server + Rust client
The Rust server currently starts with a self-signed certificate, so the client example below uses `--insecure`.

Start a local server:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Connect with a private key:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Run a remote command instead of requesting a shell:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

### Go server for public-facing deployment features
If you need the current public-certificate automation, secret URL path, proxy jump, or forwarding CLI surface, use the Go binaries today.

Example Go server with a public certificate:

```bash
ssh3-server -generate-public-cert my-domain.example.org -url-path /ssh3
```

Example Go client:

```bash
ssh3 -privkey ~/.ssh/id_ed25519 username@my-domain.example.org/ssh3
```

For the release server, connect with:

```bash
ssh3 max@my-server.example.org/ssh3-term -privkey ~/.ssh/id_ed25519
```

### File transfer

Stage 2 adds an `ssh3 -f` mode over a dedicated SFTP channel (created
files belong to the session user). Path isolation follows the sshd model by
default (`-sftp-jail chroot`): the server re-execs a short-lived per-session
child that chroots into the user's home and drops to the user's uid/gid
before touching any path — confinement is the kernel's, and the
network-facing process never opens user files. `-sftp-jail lexical` keeps
the historical in-process jail (a lexical prefix check; the server process's
own privileges apply — only sensible for an unprivileged single-user
server):

```bash
# upload a file (remote operand last)
ssh3 -f ~/report.pdf max@my-server.example.org/ssh3-term:docs/report.pdf

# upload into an existing remote directory, recursively
ssh3 -f -r ~/project-dir max@my-server.example.org/ssh3-term:backups/

# download (remote operand first)
ssh3 -f max@my-server.example.org/ssh3-term:logs/app.log ./app.log

# resume interrupted transfers instead of overwriting
ssh3 -f --continue big-disk-image.raw max@my-server.example.org/ssh3-term:images/raw

# force SHA-256 verification by re-reading the remote file
# (automatic for transfers over 32 MiB)
ssh3 -f --checksum data.bin max@my-server.example.org/ssh3-term:data.bin
```

Notes: the port defaults to 443 and the URL path to `/ssh3-term`; override
them with `-P` and `-U`, or spell the operand as
`user@host:port/url_path:remote_path`. Non-regular files (symlinks, device
nodes) are skipped during recursive transfers, and an empty directory is
created on the other side.

## Control master (connection multiplexing)

One authenticated connection shared by many invocations - the first run
performs the handshake, later runs reuse it through a Unix socket
(stage 3.5):

```bash
# start a persistent master in the background (returns immediately)
ssh3 -control-master=yes -control-persist=yes user@host

# subsequent invocations act as slaves: no new handshake, ~5x faster startup
ssh3 -control-master=auto user@host 'uptime'
ssh3 -control-master=auto user@host 'tail -n 5 /var/log/syslog'
ssh3 -control-master=auto -forward-tcp 8080/127.0.0.1@80 user@host 'sleep 30'

# shut the master down
ssh3 -O exit -control-path ~/.ssh3/cm-user@host:443 user@host
```

| Flag | Meaning |
|------|---------|
| `-control-master no\|yes\|auto` | `auto` reuses a running master and starts one if none exists; `yes` always starts one; default `no` |
| `-control-path PATH` | control socket path; default `~/.ssh3/cm-<user>@<host>:<port>`, permissions 0600 |
| `-control-persist no\|yes\|<seconds>` | keep the master in the background after sessions end; `yes` = forever, a number = idle timeout |
| `-O check\|stop\|exit` | control operation on a running master; the target operand is still needed unless an explicit `-control-path` is given, and an unknown value is rejected up front with the list of supported ones |

Notes: the master is a detached copy of this binary (`SSH3_CM_DAEMON=1`);
every slave session, TCP/UDP forward and agent forwarding is multiplexed
over the master's single QUIC connection. The measured median of 100
sequential execs drops from ~130 ms (cold, one handshake each) to ~24 ms
(~17%) with exactly one handshake. Limitations: `-proxy-jump` is
incompatible (mixing it with `-control-master` is an error), Windows is not
supported. Interactive pty slave sessions relay terminal resizes and
out-of-band signals through the master. A control socket left behind by a
killed master is detected and removed instead of failing with
`EADDRINUSE` for the full wait deadline, so a stale path no longer blocks
the next start.

### Control operations

| Operation | Behaviour |
|-----------|-----------|
| `-O check` | print the master status (pid, uptime, active sessions, forwarded channels) on stdout and exit 0 |
| `-O stop` | stop the master and wait until the control socket is actually released |
| `-O exit` | stop the master (historical behaviour) |

`check` costs one control round trip and no session, so it is cheap enough
for scripts and orchestrators to poll. With no master listening it fails
with an explicit error and a non-zero exit code instead of hanging. An
operation the build does not know is refused by the master with a readable
error, and the connection stays usable for a correct retry.

All three operations are reachable from the command line: `check`, `stop` and
`exit` are dispatched in both the `-control-path` fast path and the normal
path, and a value outside the set is rejected up front with the list of
supported operations, before any key or known-hosts file is read:

```bash
# ask a running master for its status
ssh3 -O check user@host

# stop it and wait until the control socket is actually released
ssh3 -O stop user@host
```

`exit` deliberately stays on the historical control frame so that masters
from v0.1.22/v0.1.23 still shut down correctly. The newer operations talk to
a master that predates them with an explicit *"the control master does not
support … control operation"* error, so an old peer rejects them fast rather
than leaving the client waiting.

## Port forwarding
Local TCP and UDP forwards run on the client, bridged over the ssh3
connection (`local_port/remote_ip@remote_port`):

```bash
ssh3 -forward-tcp 8080/10.0.0.10@80 user@host
ssh3 -forward-udp 5353/192.0.2.1@53 user@host
```

`-N` holds the connection open for the forwards without running a session;
`Ctrl+C` tears it down:

```bash
ssh3 -N -forward-tcp 8080/10.0.0.10@80 user@host
```

### Reverse forwarding (`-R`)

`-R` asks the **server** to bind a listener and bridge every connection it
accepts back to a target on the client side.

```bash
# the server binds 127.0.0.1:8080 and bridges it to the local 127.0.0.1:80
ssh3 -N -R 8080:127.0.0.1:80 user@host

# a UDP peer on the server reaches the local resolver
ssh3 -N -R 5353/udp:127.0.0.1:53 user@host

# bind on every interface (the server logs a warning for a wide bind)
ssh3 -N -R '*:8080:127.0.0.1:80' user@host
```

The flag is `[bind_address:]bind_port[/udp]:target_host:target_port` and can
be repeated. TCP is the default, the `/udp` suffix after the bind port
selects UDP. Without a bind address — and with `localhost`, `127.0.0.1` or
`::1` — the server binds its loopback only; `*` (like `0.0.0.0` and `::`)
requests a wildcard bind, which the server allows but logs a warning for. The
**target is resolved on the client**, like OpenSSH does, so the server only
ever receives an IP literal. `-N` is the usual companion: without a session
nothing else would start the dispatch loop for the server-initiated channels.

Semantics: each client `reverse-forward` control channel carries one bind
request as channel data, and the server answers with the bound port — bind
port `0` asks for an ephemeral one and the actual port is logged. Every
accepted connection is then mirrored back as a **server-initiated
`forwarded-tcp` channel** whose additional header bytes carry the client-side
target (UDP uses one `forwarded-udp` channel per remote peer, like the
existing direct UDP forwarding). The client only bridges a forwarded channel
whose target was actually requested with `-R`, so a compromised server cannot
make the client dial arbitrary local endpoints, and at most 64 forwarded
channels are open at once per conversation. Closing the control channel or
the connection releases the bind.

`-R` is rejected at the command line together with `-control-master` and
`-f`. An older server that does not know the channel closes it without a
reply, which the client reports as *"the server does not support reverse
forwarding"* instead of hanging — a server from v0.1.23 or newer is required.

### Dynamic SOCKS forwarding (`-D`)

`-D [bind_address:]port` opens a local SOCKS5 proxy whose connections are
dialed by the remote peer, the OpenSSH `-D` equivalent:

```bash
# SOCKS5 proxy on 127.0.0.1:1080, interactive session unaffected
ssh3 -D 1080 user@host

# listen on every interface and hold the connection open only for the proxy
ssh3 -N -D '*:1080' user@host

# let the kernel pick the port; the chosen one is logged
ssh3 -D 0 user@host
```

The proxy speaks SOCKS5 with the *no authentication required* method only (it
binds a local listener and forwards the connection over ssh3 itself, so it
never sees credentials), supports the `CONNECT` command, and accepts IPv4,
IPv6 and domain address types. An omitted bind address listens on loopback,
`*` on every interface; an IPv6 literal must be bracketed, so a bare
`::1:1080` is refused instead of being misread. Like the direct forwards, the
dynamic forward can be combined with a session or with `-N`; with `-N` the
client starts the channel dispatch loop itself.

The protocol uses two channel types:

1. The client opens one `dynamic-forward` **control channel** and sends a
   bind announcement as channel data. The server never binds anything — it
   only confirms that it will serve the client's SOCKS listener.
2. For every connection the SOCKS listener accepts, the client opens a
   `dynamic-forward-tcp` channel carrying the target address. The server
   resolves that address, dials it itself, and bridges the channel with the
   TCP connection. A **hostname is passed through as is** and resolved by the
   server, because a SOCKS client often only knows a name.

No new message-type id was introduced: `ParseMessage` panics on unknown ids,
which would crash older peers instead of letting them reject the request
gracefully. Every payload therefore travels as ordinary channel data behind a
versioned prefix (protocol version 1 + message kind), so an old peer simply
never sees it.

Per connection the server answers with the outcome of the dial, so a name
resolution or connection failure reaches the SOCKS client as a readable
reason instead of a silent hang, and the textual reason is mapped back to the
matching SOCKS5 reply code (`connection refused`, `host unreachable`,
`ttl expired`, …) so the client does not see a blanket "general failure". At
most 64 `dynamic-forward-tcp` channels are bridged at once per conversation,
and closing the control channel or the conversation tears down every live
bridge. Both halves are in the unreleased tree, so `-D` needs a server built
from this source.

## Familiar ssh(1) flags
### Forced pseudo-terminal (`-t`)

Without a terminal on the local side — a pipe, a cron job, a detached
invocation — no PTY is requested and remote full-screen programs refuse to
start. `-t` forces one:

```bash
# run a full-screen program with a pty even though stdin is a pipe
ssh3 -t user@host 'htop'

# interactive shell with a pty, geometry from the local console
ssh3 -t user@host
```

The terminal type is taken from `$TERM` (`xterm` when unset) and the geometry
from the local console, falling back to **80x24** when it cannot be queried —
a PTY with a default geometry still beats a raw pipe. `SIGHUP`, `SIGINT`,
`SIGQUIT` and `SIGTERM` are forwarded to the remote PTY, and on unix
`SIGWINCH` becomes a window-change request, so `ssh3 -t user@host top` stays
resizable. On Windows there is no `SIGWINCH`: the console reports a resize as
an event rather than a signal, so the geometry sent with the PTY request
stands for the whole session.

### Subsystem requests (`-s`)

`-s NAME` requests a remote subsystem instead of a shell or a command:

```bash
# interactive sftp shell over the dedicated sftp channel
ssh3 -s sftp user@host
```

`sftp` is special-cased onto the interactive SFTP client, whose commands are
`pwd`, `ls`, `cd`, `get`, `put`, `mkdir`, `rm`, `rmdir`, `help`, `quit`/`exit`
— the useful part of `sftp(1)` for a prompt-driven session. Any other name
is sent as a subsystem request on a session channel, exactly as `ssh(1)`
does; the bundled Go server answers such a request with *not implemented*, so
a custom name only pays off against a server that serves subsystems. With
`-t` the PTY is requested before the subsystem.

`-s` owns the session channel, so it is refused at the command line together
with `-f`, `-N`, `-forward-agent`, `-R` and a remote command.

### Alternative configuration file (`-F`)

`-F PATH` reads a per-user configuration file other than `~/.ssh/config`;
without `-F` the client reads `~/.ssh/config` as usual. The path is used
verbatim, like OpenSSH, so a relative path stays relative to the current
directory:

```bash
ssh3 -F ./ci/ssh_config user@host 'uptime'
ssh3 -F /home/deploy/.ssh/config.work user@host
```

Everything described in the next section — `Host`, `Match`, `Include` — is
resolved from that file in exactly the same way. A path that cannot be read
does not abort the connection: a read error is reported on stderr and ignored,
and a file that simply does not exist is skipped silently.

## Client configuration (~/.ssh/config)
Beyond `HostName`, `Port`, `User`, and `IdentityFile`, the client honors per
`Host` pattern: `ProxyJump` (interpreted as an ssh3 UDP proxy jump: the jump
host must run ssh3-server), `UDPProxyJump` (fork extension, same semantics),
`ForwardAgent`, and `ServerAliveInterval` (seconds; tunes the QUIC
keepalive, default 1).

### `Match` blocks
`Match` is resolved by a pre-parser that flattens the blocks applying to the
requested alias before the ssh_config decoder runs, so the usual
first-obtained-value-wins priorities of `ssh_config(5)` are preserved.
Supported criteria: `all`, `final`, `host`, `originalhost`, `user`,
`localuser` and `exec`, with `!` negation and glob patterns.
Configs without any `Match` block take an untouched fast path.

```text
Host example.lan
    User deploy
    Match originalhost web*
        Port 2222
    Match exec "test -f /srv/maintenance"
        ForwardAgent no
```

Two ssh3-specific simplifications follow from the fact that the config is
applied in a single pass and hostnames are never canonicalized: `final`
always matches and `canonical` never does. `host` and `user` are evaluated
against the evolving target, so a `HostName` or `User` set by an earlier
applicable block is visible to the later `Match` blocks. `exec` runs through
`sh -c` on unix and `cmd /c` on Windows, and matches on exit status 0.

### `Match` inside `Include` files
`Include` is expanded by the same pre-parser, recursively, *before* anything
else is parsed — the content of an included file takes the place of the
directive and continues the surrounding `Host` or `Match` block, exactly as
in OpenSSH.

```text
Include ~/.ssh/config.d/*.conf

# ~/.ssh/config.d/web.conf
Match host web*
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_web
```

Without this, any `Match` reached through an `Include` aborted the ssh_config
decoder and the whole `~/.ssh/config` was discarded. Now an included `Host`
or `Match` block goes through the same alias and `Match` filtering as the
main file. Glob patterns in `Include` targets, nested includes, a
cyclic-include guard and a recursion depth limit of 16 are supported. A
missing or unreadable include is skipped rather than invalidating the rest of
the configuration, and a `Match` parse error names the included file and the
line it really comes from.

### SSHFP host verification (RFC 4255)
The SSHFP engine checks the type-44 DNS records published for a host against
the real fingerprint of the presented host key. The fingerprint is taken
over the **DER X.509 host certificate**: ssh3 pins certificates rather than
raw SSH public keys. The DNS wire format is built and parsed in-tree, so no
third-party resolver is required.

It is off by default, as in OpenSSH, and is enabled with `-o
VerifyHostKeyDNS=...` or the same keyword in `~/.ssh/config`, with the usual
source precedence (`-o` > `~/.ssh/config`, and the default stays off):

```bash
# refuse the host when its published SSHFP records do not match its key
ssh3 -o VerifyHostKeyDNS=yes user@host

# restrict the lookup to certain host key algorithms
ssh3 -o VerifyHostKeyDNS=yes:ed25519,rsa user@host

# the same keyword per host in ~/.ssh/config
```

```text
Host example.lan
    VerifyHostKeyDNS yes:ed25519
```

Accepted values:

| Value | Meaning |
| --- | --- |
| `no` (also `false`, `off`, empty) | no lookup at all — the default, so no DNS traffic and no added latency |
| `ask` | check the records when they are published |
| `yes` (also `true`, `on`) | check the records and require a match |
| `yes:algo[,algo...]` | as above, restricted to the listed host key algorithms |

The comparison is case-insensitive and surrounding whitespace is ignored. The
algorithm list accepts the short and the full public-key names — `rsa`,
`ssh-rsa`, `dsa`, `ssh-dss`, `ssh-dsa`, `ecdsa`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `sk-ecdsa-sha2-nistp256`,
`ed25519`, `ssh-ed25519` — plus the digest names `sha1` and `sha256`, which
OpenSSH also accepts for compatibility. A host key outside the list is simply
not covered by the request, and the lookup is skipped for it. An unknown
value or algorithm is rejected before the connection is set up, with the same
*"Bad configuration option"* exit as any other malformed `-o`.

The policy is deliberately conservative:

- **Only a mismatch refuses the host** — records were published, were
  fetched, and none of them matches the presented key. NXDOMAIN, an empty
  answer, a truncated datagram, a timeout, an unavailable resolver and
  network errors are all *soft skips*: the connection continues on the
  known_hosts decision alone. It is a strictly additional signal on top of
  the known_hosts check, never a replacement.
- `ask` does not prompt. A mismatch under `ask` is refused, with a warning
  naming the option that could override it.
- With `-o StrictHostKeyChecking=no` a mismatch only warns and the
  connection continues, exactly as the pinned-certificate check does for a
  changed certificate.
- The exchange is bounded by a **2 s** deadline by default, and the
  configured DNS servers are queried in order.
- The lookup happens right after the dial, on the same certificate the
  known_hosts check used, and queries the bare DNS name (`user@` and `:port`
  carry no DNS meaning). `-insecure` skips host verification entirely, so it
  skips SSHFP as well.
- On Windows the resolver configuration lives in the registry rather than in
  `/etc/resolv.conf`, so the servers are read from the local adapters through
  `GetAdaptersAddresses`. If that enumeration yields nothing, the lookup is a
  soft skip rather than a failure.
- Record algorithms RSA, DSA, ECDSA and Ed25519 are recognised; SHA-1 and
  SHA-256 fingerprints are both computed. RSA, ECDSA and Ed25519 host keys
  are matched against them.

The verification runs in the unreleased tree, so it needs both a client and a
server built from this source to be exercised end to end.


## Authentication
### Public key
Rust client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

The server reads `~/.ssh3/authorized_identities` or the standard `~/.ssh/authorized_keys` of the target user.

### SSH agent
Rust client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  https://127.0.0.1:4433/ssh3-term
```

To forward the local agent into the remote session:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  --forward-agent \
  https://127.0.0.1:4433/ssh3-term
```

### Password
Go server (amd64 release packages ship the backend compiled in, **enabled by default**). Turn it off with `SSH3_ENABLE_PASSWORD_LOGIN=0` in `/etc/ssh3/ssh3-server.env` or `-enable-password-login=false`:

```bash
ssh3-server ... -enable-password-login
```

or, for the systemd service, set in `/etc/ssh3/ssh3-server.env`:

```bash
SSH3_ENABLE_PASSWORD_LOGIN=1
```

and restart the service (`sudo systemctl restart ssh3-server`). Connect with the Go client:

```bash
ssh3 -use-password username@my-server.example.org/ssh3-term
```

The Go client prompts for the password on the terminal; it is never passed as a command-line argument.

Rust client/server equivalent:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --enable-password-login
```

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --password-file /path/to/password.txt \
  https://127.0.0.1:4433/ssh3-term
```

Note: arm server builds are compiled with `-tags disable_password_auth` (key-only); there the password path exists only in custom builds.

### OpenID Connect
Rust client OIDC uses flags rather than a config file:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --use-oidc https://issuer.example \
  --oidc-client-id your-client-id \
  --oidc-client-secret-file /path/to/oidc-client-secret.txt \
  https://127.0.0.1:4433/ssh3-term
```

Authorized OIDC identities can be listed in `authorized_identities` alongside public keys:

```text
oidc <client_id> <issuer_url> <email>
```

## Testing
The Rust workspace is the primary verification path in this repository.

Run the full Rust suite:

```bash
cargo test
```

Run the deepest Rust/Go interoperability matrix:

```bash
cargo test -p ssh3-client
```

That interop suite exercises real Rust and Go binaries against each other, including:

- Exec and shell sessions
- PTY allocation, resize, and signal forwarding
- Public-key, password, and OIDC auth
- SSH agent auth and agent forwarding
- TCP and UDP forwarding

When running Go commands directly, the vendored dependencies are enough:

```bash
go build ./...
```

## Known Gaps
- The Rust server is intentionally minimal today: self-signed certificates only, no secret URL path, and no public certificate automation.
- The Rust CLI does not yet expose TCP forwarding, UDP forwarding, or proxy jump flags even though the underlying runtime is implemented and tested.
- Reverse forwarding (`-R`) and dynamic SOCKS forwarding (`-D`) exist in the Go client and server only, and both are newer than the last release: a server that predates them rejects the request with an explicit "not supported" error.
- The Windows client has no SSH agent forwarding and does not forward window resizes (Go has no `SIGWINCH` there); the first connection to a self-signed server requires a pinned certificate in `known_hosts` because the interactive TOFU prompt needs a Unix-style tty.
- The Go server does not implement subsystem requests, so only the `sftp` subsystem (`ssh3 -s sftp`) is usable today.

## Security
SSH3 is promising, but this project still needs substantial review before it should be trusted in production. The protocol surface combines TLS 1.3, QUIC, HTTP authorization, and SSH-style channel semantics, so the right standard is a long period of review and interoperability hardening, not “it seems to work on my machine”.

Use it in labs, CI, private environments, and interop experiments. Do not rely on it yet as a drop-in production replacement for OpenSSH.

## License
The project is licensed under the [Apache License 2.0](LICENSE), inherited from the upstream [francoismichel/ssh3](https://github.com/francoismichel/ssh3) project. Modifications made by this fork, including the documentation, are distributed under the same Apache-2.0 terms.
