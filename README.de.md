<div align="center">
<img src="resources/figures/ssh3.png" style="display: block; width: 60%">
</div>

> [!NOTE]
> SSH3 ist weiterhin experimentell, und der Protokollname kann sich noch ändern. Das Protokoll bleibt SSH-typische Sitzungs- und Kanalsemantik über QUIC und HTTP/3 Extended CONNECT, aber die Implementierung und das drumherum entwickeln sich weiter.

> [!WARNING]
> **Der Rust-Workspace unter `crates/` ist seit 2026-10-13 eingefroren (dormant)**: er wird nicht in CI gebaut, in keinem Release ausgeliefert, und die Audit-Fundstellen darin (F-16, F-20, der F-19-Client-Rest) sind mit dem Code eingefroren — keine Fixes geplant. Siehe `crates/FROZEN.md`. Das einzige ausgelieferte Produkt ist die Go-Implementierung.

# SSH3 over HTTP/3
[English](README.md) | [Русский](README.ru.md) | **Deutsch**

SSH3 abbildet RFC-4254-artige Sitzungssemantik auf QUIC, TLS 1.3 und HTTP/3 Extended CONNECT. Das Projekt möchte vertraute SSH-Workflows erhalten und gleichzeitig HTTP-native Authentifizierung und QUIC-native Transportfunktionen wie Datagram-Forwarding hinzufügen.

Dieses Repository enthält derzeit zwei Implementierungen:

- Den ursprünglichen Go-Client und -Server in [`cmd/ssh3`](cmd/ssh3) bzw. [`cmd/ssh3-server`](cmd/ssh3-server)
- Ein laufendes Rust-Rewrite in [`crates/`](crates)

> [!WARNING]
> Betrachten Sie keine der Implementierungen als produktionsreif. Protokoll und Code befinden sich in aktiver Entwicklung; das Rust-Rewrite konzentriert sich in erster Linie auf Korrektheit und Interoperabilität, nicht auf Produktvollständigkeit.

## Über den nagual2-Fork
Dieser Fork zielt darauf ab, die Go-Implementierung zu einem praktischen Alltagswerkzeug zu machen. Diese README basiert auf der README des Upstream-Projekts und wurde von den Fork-Maintainern geändert; nur den Fork betreffende Änderungen werden in [CHANGELOG.md](CHANGELOG.md) nachverfolgt:

- **Der Windows-Client ist vollwertig.** Seit v0.1.8 kompiliert der Client für Windows und unterstützt interaktive PTY-Sitzungen: VT-Eingabe/-Ausgabe, UTF-8-Konsolcodepage, echte Konsolengröße, Weiterleitung von `SIGINT`/`SIGTERM` und einen 80x24-PTY-Fallback, wenn die Konsolengröße nicht ermittelt werden kann.
- **Server-Pakete: standardmäßig Schlüssel, Passwörter als Opt-in.** Das Release-`.deb` liefert einen systemd-Dienst (`ssh3-server.service`, UDP 443, geheimer URL-Pfad); OIDC ist nicht konfiguriert, und das Post-Install-Skript erzeugt ein selbstsigniertes ed25519-Zertifikat mit IP/DNS-SANs. In amd64-Builds ist das Passwort-Backend einkompiliert und standardmäßig aktiviert (`SSH3_ENABLE_PASSWORD_LOGIN=0` schaltet es ab); arm-Server-Builds sind nur mit Schlüsseln.
- **systemd-Unit mit OpenSSH-Parität.** Der Unit enthält keine Sandbox-Direktiven (`CapabilityBoundingSet`, `NoNewPrivileges`, `Protect*`): Der Root-Daemon startet jede Sitzung mit der uid/gid des authentifizierten Benutzers (wie sshd), sodass `sudo` innerhalb einer Sitzung die vollen Root-Capabilities zurückerlangt — tcpdump, trafshow, modprobe und sysctl funktionieren. `KillMode=process` erhält aktive Sitzungen über Daemon-Neustarts hinweg, wie in Debians `ssh.service`. Die Vertrauensgrenze ist die Schlüsselauthentifizierung, nicht die Unit-Sandbox.
- **Statistik-Banner beim Login.** Interaktive Sitzungen zeigen vor dem Shell-Prompt Uptime, Load, Arbeitsspeicher und Festplatte (`exec`-Anfragen bleiben unberührt).
- **Locale- und Shell-Fixes.** Der Server reicht `LANG`/`LC_*` aus seiner systemd-Umgebung an die Benutzer-Shells weiter und startet die echte Login-Shell des Kontos aus `/etc/passwd` statt eines hartkodierten `/bin/sh`.
- **CI.** Jedes `v*`-Tag erzeugt Release-Archive und ein `.deb` via goreleaser; jeder Push nach `main` erzeugt Windows-Client-Artefakte.
- **Spezifikation des Wire-Protokolls.** Das Protokoll, das dieser Fork spricht, ist als Projektdokument im Repository des C17-Ports festgehalten: [SSH3 wire protocol, rev nagual2/1](https://github.com/nagual2/ssh3-c/blob/main/docs/SPEC-wire.md) — das draft-michel-remote-terminal-http3-00-Gerüst, an beiden lebenden Implementierungen (dieser Fork + ssh3-c) verifiziert.

## Download & Installation
Die Assets gibt es im [neuesten Release](https://github.com/nagual2/ssh3-go/releases/latest):

| Datei | Zweck |
| --- | --- |
| `ssh3-go_client_<ver>_windows_amd64.zip` | Windows-Client (`ssh3.exe`) |
| `ssh3-go_client_<ver>_<os>_<arch>.tar.gz` | Client für Linux, macOS, FreeBSD, OpenBSD |
| `ssh3-go_server_<ver>_linux_<arch>.tar.gz` | Linux-Server-Binaries |
| `ssh3-go_<ver>_amd64.deb` | Server-+-Client-Paket für Debian/Ubuntu/Mint (systemd-Dienst, standardmäßig Schlüssel; Passwort-Authentifizierung als Opt-in auf amd64) |

Installation des Debian-Pakets:

```bash
sudo dpkg -i ssh3-go_0.1.26_amd64.deb
```

Das Paket `ssh3-go` ersetzt das bisherige Paket `ssh3` direkt (Conflicts/Replaces); Binärdateien (`ssh3`, `ssh3-server`) und die Unit `ssh3-server.service` behalten ihre Namen.

Der Dienst lauscht auf UDP 443 unter dem geheimen URL-Pfad `/ssh3-term`. Die Konfiguration liegt in `/etc/ssh3/ssh3-server.env` (Logdatei und -level, `LANG`), die systemd-Unit in `/usr/lib/systemd/system/ssh3-server.service`; ein selbstsigniertes ed25519-Zertifikat mit IP/DNS-SANs wird bei der Installation in `/etc/ssh3/` erzeugt, falls es fehlt.

### Serverkonfiguration
Das Release-Paket wird über die systemd-`EnvironmentFile` unter `/etc/ssh3/ssh3-server.env` konfiguriert:

| Variable | Standard | Zweck |
| --- | --- | --- |
| `SSH3_LOG_FILE` | `/var/log/ssh3.log` | Server-Logdatei |
| `SSH3_LOG_LEVEL` | `info` | Log-Ausführlichkeit (`trace`, `debug`, `info`, `warn`, `error`) |
| `SSH3_GATEWAY_PORTS` | `no` | GatewayPorts-Richtlinie für Reverse-(-R-)Weiterleitungen: `no` erzwingt angeforderte Nicht-Loopback-Binds zurück auf den Loopback, `clientspecified` übernimmt die angeforderte Adresse, `yes` bindet die Wildcard-Adresse |
| `SSH3_MAX_REVERSE_FORWARDS` | `10` | Maximale aktive -R-Listener pro Benutzer |
| `SSH3_MAX_UNAUTH_CONVERSATIONS` | `100` | Maximale nicht authentifizierte Konversationen vor Ablehnungen (DoS-Schutz) |
| `SSH3_MAX_PASSWORD_FAILURES` | `10` | Fehlgeschlagene Passwortversuche vor der Kontosperrung |
| `SSH3_PASSWORD_LOCKOUT_SECONDS` | `60` | Dauer der Passwort-Brute-Force-Sperre in Sekunden |
| `LANG` | `C.UTF-8` | Locale, die an Benutzer-Shells weitergereicht wird |

Änderungen anwenden: `sudo systemctl restart ssh3-server`.

Client und Server akzeptieren QUIC-Tuning-Flags für Bulk-Transfers: `-initial-packet-size` (initiale QUIC-Paketgröße in Bytes, Standard `1350`), `-stream-rx-mb` (Flow-Control-Empfangsfenster pro Stream in MiB, Standard `8`) und `-conn-rx-mb` (Empfangsfenster auf Verbindungsebene in MiB, Standard `16`).

## Interaktive Escape-Sequenzen
Ein Escape-Zeichen am Zeilenanfang steuert den Client: `~.` trennt die Verbindung, `~^Z` stoppt den Client lokal (unix), `~~` sendet ein literales `~`; eine unbekannte Sequenz wird wörtlich weitergeleitet. Das Zeichen ist standardmäßig `~` und wird mit `-o EscapeChar=<Zeichen|none>` oder demselben Schlüsselwort in `~/.ssh/config` gewählt.

## Hinweise zum Windows-Client
- Flags (z. B. `-privkey`) müssen **vor** der positionalen URL stehen: Gos Flag-Parser stoppt beim ersten positionalen Argument.
- Die Konsole wird für die Sitzung auf UTF-8 und VT-Verarbeitung umgeschaltet und beim Beenden zurückgesetzt. Verwenden Sie einen Unicode-fähigen Zeichensatz (Consolas, Lucida Console).
- Es gibt kein `/dev/tty` unter Windows, daher ist die interaktive TOFU-Abfrage nicht möglich: Hinterlegen Sie das Serverzertifikat in `%USERPROFILE%\.ssh3\known_hosts` (`host:port/path x509-certificate <base64 DER>`) oder verwenden Sie bewusst `-insecure`.
- SSH-Agent-Forwarding ist nicht verfügbar (nur Unix-Sockets); Fenstergrößenänderungen werden nicht weitergeleitet (kein SIGWINCH-Äquivalent).

## Status
Die Go-Implementierung bietet weiterhin die breiteste Endbenutzer-CLI. Der Rust-Workspace deckt inzwischen den Protokollkern, QUIC/HTTP/3-Bootstrap, Authentifizierung, Sitzungsverwaltung, PTY-Shells, Resize- und Signal-Forwarding, Forwarding-Runtimes sowie echte Rust<->Go-Interoperabilitätstests ab.

Rust ist kein reines Codec-Experiment mehr: funktionierende Client- und Server-Binaries existieren, aber einige betriebliche Funktionen gibt es heute nur in Go.

## Funktionsstatus
| Funktion | Go CLI/Server | Rust | Hinweise |
| --- | --- | --- | --- |
| QUIC + HTTP/3 SSH3-Transport | Ja | Ja | Rust nutzt `quinn` plus einen gepatchten vendored `h3`-Crate. |
| Sitzung: Shell und Exec | Ja | Ja | Durch Unit- und Real-Binary-Interop-Tests abgedeckt. |
| PTY-Shell, Resize und Signal-Forwarding | Ja | Ja | Real-Binary-Interop für Resize und Signale ist beidseitig getestet. Windows-Clients erhalten ein PTY mit fester 80x24-Fallback-Geometrie. |
| Public-Key-Authentifizierung | Ja | Ja | Ed25519, P-256 und RSA sind abgedeckt. |
| Passwortauthentifizierung | Ja | Ja | Go-Passwortauthentifizierung nutzt das systemweite Shadow-Backend (CGO). amd64-Release-Server-Builds kompilieren sie ein und aktivieren sie standardmäßig; arm-Builds sind nur mit Schlüsseln. |
| OpenID-Connect-Authentifizierung | Ja | Ja | Tokens sind inzwischen per Nonce-Prüfung an die SSH3-Konversation gebunden. |
| SSH-Agent-Authentifizierung | Ja | Ja | |
| SSH-Agent-Forwarding | Ja | Ja | Nur Unix-Sockets; aus Windows-Clients nicht verfügbar. |
| Direktes TCP-Forwarding | Ja | Ja | Die Rust-Runtime unterstützt es; die Rust-CLI exponiert die Forwarding-Flags noch nicht. |
| Direktes UDP-Forwarding | Ja | Ja | Die Rust-Runtime unterstützt es; die Rust-CLI exponiert die Forwarding-Flags noch nicht. |
| Reverse-TCP/UDP-Forwarding | Ja | Nein | `-R`, derzeit nur Go. |
| Dynamisches SOCKS-Forwarding | Ja | Nein | `-D`, derzeit nur Go. |
| Proxy jump | Ja | Nein | Derzeit nur Go. |
| Geheimer URL-Pfad / versteckter Serverpfad | Ja | Nein | Derzeit nur Go. |
| Automatisierung öffentlicher Zertifikate | Ja | Nein | Der Go-Server unterstützt Let's Encrypt; der Rust-Server derzeit nur selbstsignierte Zertifikate. |

## Repository-Aufbau
- [`cmd/ssh3`](cmd/ssh3): ursprünglicher Go-Client
- [`cmd/ssh3-server`](cmd/ssh3-server): ursprünglicher Go-Server
- [`crates/ssh3-proto`](crates/ssh3-proto): Wire-Format, Nachrichten und Forwarding-Header
- [`crates/ssh3-core`](crates/ssh3-core): Conversations- und Channel-Runtime
- [`crates/ssh3-quinn`](crates/ssh3-quinn): QUIC-Bindings
- [`crates/ssh3-h3`](crates/ssh3-h3): HTTP/3-Bootstrap und CONNECT-Behandlung
- [`crates/ssh3-auth`](crates/ssh3-auth): Public-Key- und passwortnahe Hilfen sowie OIDC-Verifizierung
- [`crates/ssh3-client`](crates/ssh3-client): Rust-Client (Bibliothek und Binary)
- [`crates/ssh3-server`](crates/ssh3-server): Rust-Server (Bibliothek und Binary)
- [`internal/interop`](internal/interop): Go-Helfer für die Rust-Real-Binary-Interop-Suite

## Bauen
### Rust
Aktuelles stabiles Rust-Toolchain verwenden.

```bash
cargo build --workspace
cargo run -p ssh3-client -- --help
cargo run -p ssh3-server -- --help
```

Aktuelle Rust-CLIs:

```text
$ cargo run -p ssh3-client -- --help
Usage: ssh3-client [OPTIONS] <URL> [COMMAND]...

$ cargo run -p ssh3-server -- --help
Usage: ssh3-server [OPTIONS]
```

Beim Rust-Client sind dateibasierte Secret-Flags wie `--password-file`, `--bearer-token-file` und `--oidc-client-secret-file` zu bevorzugen: Sie lecken weniger über Shell-History, Prozesslisten und CI-Logs.

### Go
Go 1.21 oder neuer. Das Repository trägt einen vollständigen `vendor/`-Baum, die Builds unten funktionieren also so wie sie dastehen:

```bash
CGO_ENABLED=0 go build -o ssh3 ./cmd/ssh3
CGO_ENABLED=0 go build -tags disable_password_auth -o ssh3-server ./cmd/ssh3-server
```

Release-Client-Builds und arm-Server-Builds verwenden `CGO_ENABLED=0` mit `-tags disable_password_auth` — Passwortauthentifizierung ist dann vollständig aus dem Binary entfernt. Der amd64-Release-Server wird mit CGO und ohne den Tag gebaut: das Shadow/crypt-Backend ist einkompiliert und standardmäßig aktiviert (`SSH3_ENABLE_PASSWORD_LOGIN=0` schaltet es ab). Die Release-Client-Builds können sich nicht per Passwort authentifizieren. Wer einen passwortfähigen Client im eigenen Linux-Build möchte:

```bash
CGO_ENABLED=1 go build -o ssh3-server ./cmd/ssh3-server
```

## Schnellstart
### Lokaler Rust-Server + Rust-Client
Der Rust-Server startet derzeit mit einem selbstsignierten Zertifikat, daher nutzt das Client-Beispiel `--insecure`.

Server starten:

```bash
cargo run -p ssh3-server -- \
  --bind 127.0.0.1:4433 \
  --user "$USER" \
  --require-auth \
  --authorized-identity ~/.ssh/authorized_keys
```

Verbindung mit privatem Schlüssel:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Remote-Befehl statt Shell:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term \
  -- "printf 'hello from ssh3\n'"
```

### Go-Server für öffentliche Einsatzszenarien
Wer Automatisierung öffentlicher Zertifikate, geheimen URL-Pfad, Proxy jump oder das Forwarding-CLI braucht, nutzt heute die Go-Binaries.

Beispiel-Go-Server mit öffentlichem Zertifikat:

```bash
ssh3-server -generate-public-cert my-domain.example.org -url-path /ssh3
```

Beispiel-Go-Client:

```bash
ssh3 -i ~/.ssh/id_ed25519 username@my-domain.example.org/ssh3
```

Beim Release-Server:

```bash
ssh3 max@my-server.example.org/ssh3-term -i ~/.ssh/id_ed25519
```

### Dateiübertragung

Stage 2 ergänzt den `ssh3 -transfer`-Modus über einen dedizierten SFTP-Kanal (angelegte
Dateien gehören dem Sitzungsbenutzer). Die Pfad-Isolation folgt standardmäßig
dem sshd-Modell (`-sftp-jail chroot`): der Server startet pro Sitzung einen
kurzlebigen Kindprozess, der in das Home-Verzeichnis des Benutzers chrootet und
vor dem ersten Pfadzugriff auf dessen uid/gid wechselt — die Einschließung
übernimmt der Kernel, und der netzseitige Prozess öffnet nie Benutzerdateien.
`-sftp-jail lexical` erhält das historische In-Process-Jail (lexikalische
Präfixprüfung; es gelten die eigenen Privilegien des Serverprozesses — nur
sinnvoll für einen unprivilegierten Single-User-Server):

```bash
# Datei hochladen (Remote-Operand zuletzt)
ssh3 -transfer ~/report.pdf max@my-server.example.org/ssh3-term:docs/report.pdf

# Verzeichnis rekursiv hochladen
ssh3 -transfer -r ~/project-dir max@my-server.example.org/ssh3-term:backups/

# Herunterladen (Remote-Operand zuerst)
ssh3 -transfer max@my-server.example.org/ssh3-term:logs/app.log ./app.log

# Unterbrochene Übertragungen fortsetzen statt zu überschreiben
ssh3 -transfer --continue big-disk-image.raw max@my-server.example.org/ssh3-term:images/raw

# SHA-256-Prüfung durch erneutes Lesen der Remote-Datei erzwingen
# (automatisch bei Übertragungen über 32 MiB)
ssh3 -transfer --checksum data.bin max@my-server.example.org/ssh3-term:data.bin
```

Hinweise: Standardport 443, URL-Pfad `/ssh3-term`; überschreibbar mit `-p`
(ssh2-Form) und `-U`, oder als vollständige Form
`user@host:port/url_path:remote_path` (das Fork-eigene `-P` gilt im
Übertragungsmodus als veralteter Alias von `-p`). Unreguläre Dateien
(Symlinks, Geräte) werden bei rekursiven Übertragungen übersprungen, ein
leeres Verzeichnis wird auf der Gegenseite angelegt. Die alte Fork-eigene
Übertragungsform `-f` ist eingestellt — das Flag bedeutet jetzt das
ssh2-Backgrounding (Paritätstabelle oben).

## Control Master (Verbindungsmultiplexing)

Eine authentifizierte Verbindung für viele Aufrufe - der erste Lauf macht
den Handshake, weitere nutzen ihn über einen Unix-Socket (Stage 3.5):

```bash
# persistenten Master im Hintergrund starten (kehrt sofort zurück)
ssh3 -M -o ControlPersist=yes user@host

# weitere Aufrufe laufen als Slave: kein neuer Handshake, ~5x schneller Start
ssh3 -control-master=auto user@host 'uptime'
ssh3 -control-master=auto user@host 'tail -n 5 /var/log/syslog'
ssh3 -control-master=auto -L 8080:127.0.0.1:80 user@host 'sleep 30'

# Master beenden
ssh3 -O exit -S ~/.ssh3/cm-user@host:443 user@host
```

| Flag | Bedeutung |
|------|-----------|
| `-M` | Master-Modus (ssh2 `-M`), identisch zu `-control-master yes` |
| `-S PFAD` | Pfad des Steuerungs-Sockets (ssh2 `-S`), identisch zu `-control-path PFAD` |
| `-control-master no\|yes\|auto` | `auto` nutzt einen laufenden Master und startet sonst einen; `yes` startet immer; Standard `no` (auch `-o ControlMaster=…`) |
| `-control-path PFAD` | Pfad des Steuerungs-Sockets; Standard `~/.ssh3/cm-<user>@<host>:<port>`, Rechte 0600 (auch `-o ControlPath=…`) |
| `-control-persist no\|yes\|<Sekunden>` | Master nach Sitzungsende im Hintergrund halten; `yes` = unbegrenzt, Zahl = Idle-Timeout (auch `-o ControlPersist=…`) |
| `-O check\|stop\|exit` | Steuerungsoperation auf einem laufenden Master; das Ziel-Operand wird weiterhin gebraucht, sofern nicht explizit `-control-path` gesetzt ist, und ein unbekannter Wert wird vorab mit der Liste der unterstützten Werte abgelehnt |

Hinweise: der Master ist eine abgelöste Kopie dieses Binärprogramms
(`SSH3_CM_DAEMON=1`); jede Slave-Sitzung, TCP/UDP-Weiterleitung und das
Agent-Forwarding werden über die eine QUIC-Verbindung des Masters
multiplext. Der Median von 100 aufeinanderfolgenden Execs sinkt von
~130 ms (kalt, je ein Handshake) auf ~24 ms (~17%) bei genau einem
Handshake. Einschränkungen: `-J`/`-proxy-jump` ist inkompatibel (die Kombination
mit `-control-master` ist ein Fehler), Windows wird nicht unterstützt.
Interaktive pty-Slave-Sitzungen leiten Fensteränderungen und außerbandige
Signale durch den Master. Ein Steuerungs-Socket, den ein abgebrochener
Master hinterlässt, wird erkannt und entfernt, statt für die gesamte
Wartefrist mit `EADDRINUSE` zu scheitern – ein veralteter Pfad blockiert den
nächsten Start also nicht mehr.

### Steuerungsoperationen

| Operation | Verhalten |
|-----------|-----------|
| `-O check` | Master-Status (pid, Laufzeit, aktive Sitzungen, weitergeleitete Kanäle) auf stdout ausgeben und mit 0 beenden |
| `-O stop` | Master beenden und warten, bis der Steuerungs-Socket tatsächlich freigegeben ist |
| `-O exit` | Master beenden (historisches Verhalten) |

`check` kostet einen Steuerungs-Roundtrip und keine Sitzung und ist damit
günstig genug, um sie aus Skripten und Orchestratoren abzufragen. Läuft kein
Master, endet der Aufruf mit einer klaren Fehlermeldung und einem
von null verschiedenen Exit-Code, statt zu hängen. Eine Operation, die der
Build nicht kennt, weist der Master mit einer lesbaren Fehlermeldung ab, und
die Verbindung bleibt für einen korrekten Wiederholungsversuch nutzbar.

`exit` bleibt bewusst auf dem historischen Steuerungsframe, damit Master der
Versionen v0.1.22/v0.1.23 weiterhin sauber herunterfahren. Die neueren
Operationen erhalten von einem älteren Master die explizite Meldung *„the
control master does not support … control operation"*, sodass ein alter Peer
sie sofort ablehnt, statt den Client warten zu lassen.

Alle drei Operationen sind über die Kommandozeile erreichbar: `check`, `stop`
und `exit` werden sowohl im `-control-path`-Schnellpfad als auch im normalen
Pfad dispatcht, und ein Wert außerhalb der Menge wird vorab mit der Liste der
unterstützten Operationen abgelehnt — noch bevor ein Schlüssel oder die
known_hosts-Datei gelesen wird:

```bash
# einen laufenden Master nach seinem Status fragen
ssh3 -O check user@host

# ihn beenden und warten, bis der Steuerungs-Socket tatsächlich freigegeben ist
ssh3 -O stop user@host
```

`exit` bleibt bewusst auf dem historischen Steuerungsframe, damit Master der
Versionen v0.1.22/v0.1.23 weiterhin sauber herunterfahren. Die neueren
Operationen erhalten von einem älteren Master die explizite Meldung *„the
control master does not support … control operation"*, sodass ein alter Peer
sie sofort ablehnt, statt den Client warten zu lassen.


## Port-Weiterleitung
Lokale Weiterleitungen werden über die ssh3-Verbindung getunnelt. Die
primäre Form ist die ssh2-Syntax `-L [bind:]port:host:hostport`,
wiederholbar; ein optionales `udp://`-Präfix wählt UDP, das es in ssh(1)
nicht gibt:

```bash
# ssh2-Form: lokal 8080 zum serverseitigen Dial auf 10.0.0.10:80
ssh3 -L 8080:10.0.0.10:80 user@host

# explizite lokale Adresse; IPv6-Literale in Klammern
ssh3 -L 127.0.0.1:8080:10.0.0.10:80 user@host
ssh3 -L '[::1]:8080:[::1]:80' user@host

# UDP als dokumentierte ssh3-Erweiterung (udp://-Präfix)
ssh3 -L udp://5353:192.0.2.1:53 user@host
```

Die Fork-eigene Form `lokaler_port/remote_ip@remote_port` bleibt als
veralteter Alias erhalten:

```bash
ssh3 -forward-tcp 8080/10.0.0.10@80 user@host
ssh3 -forward-udp 5353/192.0.2.1@53 user@host
```

`-N` hält die Verbindung für die Weiterleitungen offen, ohne eine Sitzung
zu starten; `Strg+C` baut sie ab:

```bash
ssh3 -N -L 8080:10.0.0.10:80 user@host
```

### Rückwärtige Weiterleitung (`-R`)

`-R` lässt den **Server** einen Listener binden und jede von ihm angenommene
Verbindung zurück zu einem Ziel auf der Client-Seite überbrücken.

```bash
# der Server lauscht auf 127.0.0.1:8080 und brückt auf das lokale 127.0.0.1:80
ssh3 -N -R 8080:127.0.0.1:80 user@host

# ein UDP-Peer auf dem Server erreicht den lokalen Resolver
ssh3 -N -R 5353/udp:127.0.0.1:53 user@host

# an alle Schnittstellen binden (der Server warnt vor der weiten Bindung)
ssh3 -N -R '*:8080:127.0.0.1:80' user@host
```

Das Flag hat die Form `[bind_address:]bind_port[/udp]:target_host:target_port`
und ist wiederholbar. Standard ist TCP; das Suffix `/udp` hinter dem
Bindungsport wählt UDP. Ohne Bindeadresse — und bei `localhost`, `127.0.0.1`
oder `::1` — lauscht der Server nur auf seinem eigenen Loopback; `*` (wie
`0.0.0.0` und `::`) verlangt eine Wildcard-Bindung, die der Server erlaubt,
aber mit einer Warnung protokolliert. **Das Ziel wird auf dem Client
aufgelöst**, wie es OpenSSH tut, der Server erhält also nur ein IP-Literal.
Der übliche Begleiter ist `-N`: ohne Sitzung würde niemand die Schleife für
serverseitig initiierte Kanäle starten.

Zur Semantik: jeder Steuerungskanal `reverse-forward` des Clients trägt genau
eine Bindungsanfrage als Kanaldaten, und der Server antwortet mit dem
belegten Port — der Bindungsport `0` verlangt einen ephemeren, der tatsächlich
belegte Port landet im Log. Jede angenommene Verbindung wird anschließend als
**serverseitig initiierter Kanal `forwarded-tcp`** zurückgespiegelt, dessen
zusätzliche Header-Bytes das Client-Ziel tragen (für UDP ein Kanal
`forwarded-udp` pro entferntem Peer, wie beim direkten UDP-Forwarding). Der
Client überbrückt nur Kanäle, deren Ziel tatsächlich über `-R` angefordert
wurde, ein kompromittierter Server kann den Client also nicht beliebige lokale
Ziele anwählen lassen; gleichzeitig sind höchstens 64 Kanäle pro Konversation
offen. Das Schließen des Steuerungskanals oder der Verbindung gibt die Bindung
frei.

`-R` wird auf Kommandozeilenebene zusammen mit `-control-master` und `-f`
abgelehnt. Ein alter Server, der den Kanal nicht kennt, schließt ihn ohne
Antwort, und der Client meldet das als *„the server does not support reverse
forwarding"*, statt zu hängen; ein Server ab v0.1.23 wird gebraucht.

### Dynamische SOCKS-Weiterleitung (`-D`)

`-D [bind_address:]port` öffnet einen lokalen SOCKS5-Proxy, dessen
Verbindungen der entfernte Peer aufbaut – das `-D`-Äquivalent aus OpenSSH:

```bash
# SOCKS5-Proxy auf 127.0.0.1:1080, eine interaktive Sitzung leidet nicht darunter
ssh3 -D 1080 user@host

# an allen Schnittstellen lauschen und die Verbindung nur für den Proxy halten
ssh3 -N -D '*:1080' user@host

# der Port wird vom Kernel vergeben; der gewählte landet im Log
ssh3 -D 0 user@host
```

Der Proxy spricht ausschließlich SOCKS5 *no authentication required* (er bindet
einen lokalen Listener und überbrückt die Verbindung innerhalb von ssh3, sieht
also nie Zugangsdaten), unterstützt den Befehl `CONNECT` und akzeptiert die
Adresstypen IPv4, IPv6 und Domain. Ohne Bindeadresse hängt der Listener am
Loopback, `*` an allen Schnittstellen; ein IPv6-Literal muss in eckigen
Klammern stehen, sonst wird ein nacktes `::1:1080` abgelehnt statt falsch
gelesen. Wie die direkten Weiterleitungen lässt sich der dynamische Proxy mit
einer Sitzung oder mit `-N` kombinieren; im `-N`-Fall startet der Client die
Kanalschleife selbst.

Das Protokoll nutzt zwei Kanaltypen:

1. Der Client öffnet einen Steuerungskanal `dynamic-forward` und sendet
   darin eine Bindungsankündigung als Kanaldaten. Der Server bindet nichts –
   er bestätigt nur, dass er den SOCKS-Listener des Clients bedienen wird.
2. Für jede vom SOCKS-Listener angenommene Verbindung öffnet der Client
   einen Kanal `dynamic-forward-tcp` mit der Zieladresse. Der Server löst
   diese Adresse selbst auf, baut selbst die TCP-Verbindung auf und überbrückt
   den Kanal mit dieser Verbindung. Ein **Hostname wird unverändert
   weitergereicht** und vom Server aufgelöst, weil ein SOCKS-Client oft nur
   den Namen kennt.

Es wurden bewusst **keine neuen Message-Type-IDs** eingeführt: `ParseMessage`
panicked bei unbekannten IDs, wodurch ältere Peers abstürzen würden, statt die
Anfrage sauber abzulehnen. Alle Nutzlasten laufen daher als gewöhnliche
Kanaldaten hinter einem versionierten Präfix (Protokollversion 1 +
Nachrichtenart), sodass ein alter Peer sie einfach nie sieht.

Pro Verbindung antwortet der Server mit dem Ergebnis des Verbindungsaufbaus,
sodass ein Namensauflösungs- oder Verbindungsfehler für den SOCKS-Client als
lesbarer Grund ankommt statt als stilles Hängen; der Textgrund wird auf den
passenden SOCKS5-Antwortcode abgebildet (`connection refused`,
`host unreachable`, `ttl expired`, …), der Client sieht also kein namenloses
*„general failure"*. Pro Konversation werden höchstens 64
`dynamic-forward-tcp`-Kanäle gleichzeitig überbrückt, und das Schließen des
Steuerungskanals oder der Konversation reißt alle lebenden Brücken ab. Beide
Hälften liegen im unveröffentlichten Baum, `-D` braucht also einen aus dieser
Quelle gebauten Server.

## OpenSSH-kompatible Optionen (ssh2-Kanon)

Wo der Funktionsumfang übereinstimmt, folgen die Startschlüssel ssh(1)/sshd(8)
— Skripte für OpenSSH und für die Schwester-C-Implementierung verhalten sich
gegenüber diesem Client gleich (CLI-Paritätswelle, CTO_TASK §7c). Die
Fork-eigenen Formen bleiben als veraltete Aliase erhalten: bestehende
Installationen und Skripte funktionieren weiter.

| ssh2-Form | Bedeutung | Veralteter Fork-Alias |
|---|---|---|
| `-i DATEI` | privater Schlüssel für die Public-Key-Authentifizierung | `-privkey DATEI` |
| `-V` | Version ausgeben und beenden | `-version` |
| `-A` | SSH-Agent weiterleiten | `-forward-agent` |
| `-J ZIEL[,ZIEL...]` | Proxy-Jump; jeder Hop läuft unter ssh3-server | `-proxy-jump URL` (ein Hop) |
| `-L [BIND:]PORT:HOST:PORT` | lokale Weiterleitung, wiederholbar; `udp://`-Präfix wählt UDP | `-forward-tcp/-forward-udp LOKAL/REMOTE@PORT` |
| `-M` / `-S PFAD` | Master-Modus / Steuerungs-Socket | `-control-master yes` / `-control-path PFAD` |
| `-p PORT` | Remote-Port (auch im Übertragungsmodus) | `-P PORT` (nur Übertragungsmodus) |
| `-q` | still: Diagnosen unterdrückt, Fehler bleiben | — |
| `-4` / `-6` | Adressfamilie erzwingen | — |
| `-f` | nach dem Start in den Hintergrund (ssh2 `-f`): die Sitzung löst sich vom Terminal und läuft weiter; nur nicht-interaktive Authentifizierung (Schlüssel/Agent), ein ungepinnter Host unter der Ask-Politik wird vorab abgelehnt; kombinierbar mit Befehl, `-N` oder Weiterleitungen (`-L/-D/-R`); auf Windows nicht verfügbar (läuft mit Warnung im Vordergrund) | — |
| `-transfer SRC DST` | Dateiübertragungsmodus | die Fork-eigene Übertragungsform `-f` ist eingestellt (das Flag bedeutet jetzt das ssh2-Backgrounding) |

Server (sshd(8)-Kanon): `-h SCHLÜSSEL` = Host-Key (Alias von `-key`),
`-c ZERT` = Host-Zertifikat (Alias von `-cert`), `-p PORT` = Listen-Port
(überschreibt den `-bind`-Port, die Adresse bleibt in `-bind` — QUIC braucht
eine explizite UDP-Adresse), `-V` = Version.

`-o`-Schlüssel nach dem ssh_config-Modell: `Port`, `User`, `IdentityFile`,
`LocalForward`, `RemoteForward`, `DynamicForward`, `ProxyJump`,
`ControlMaster`, `ControlPath`, `ControlPersist` (neben den bestehenden
`StrictHostKeyChecking`, `EscapeChar`, `RequestTTY`, `Term`,
`VerifyHostKeyDNS`). Präzedenz: CLI-Flag > `-o` > `~/.ssh/config`.

Die Verhaltens-Timeouts folgen dem sshd-Kanon: eine untätige Sitzung wird
nicht getötet (`ClientAliveInterval=0`-Form — der Standard-Idle-Timeout
beträgt 24 h auf beiden Enden, einstellbar mit `-max-idle-timeout`), und der
Handshake erhält die `LoginGraceTime`-Skala (120 s,
`-handshake-idle-timeout`). Root verweigert die Passwort-Authentifizierung
unbedingt (das `PermitRootLogin prohibit-password`-Analogon): Root meldet
sich nur per Schlüssel an.

## Vertraute ssh(1)-Flags
### Erzwungenes PTY (`-t`)

Fehlt lokal ein Terminal – Pipe, Cron-Job, abgesetzter Start – wird kein PTY
angefordert, und vollflächige Programme auf der Gegenseite starten nicht. `-t`
fordert es trotzdem an:

```bash
# ein Vollbildprogramm mit pty starten, auch wenn stdin eine Pipe ist
ssh3 -t user@host 'htop'

# interaktive Shell mit pty, die Geometrie kommt von der lokalen Konsole
ssh3 -t user@host
```

Der Terminaltyp wird aus `$TERM` übernommen (`xterm`, falls die Variable
nicht gesetzt ist), die Geometrie aus der lokalen Konsole, mit einem Fallback
auf **80x24**, wenn sie sich nicht ermitteln lässt: ein PTY in Standardgeometrie
ist immer noch besser als eine nackte Pipe. `SIGHUP`, `SIGINT`, `SIGQUIT` und
`SIGTERM` werden an das entfernte PTY weitergereicht, unter Unix wird
`SIGWINCH` zu einer Fenstergrößenänderungsanfrage, damit `ssh3 -t user@host top`
skalierbar bleibt. Unter Windows gibt es kein `SIGWINCH`: Die Konsole meldet
eine Größenänderung per Ereignis statt per Signal, daher gilt die mit der
PTY-Anfrage gesendete Geometrie für die ganze Sitzung.

### Subsystem-Anfragen (`-s`)

`-s NAME` fragt ein entferntes Subsystem an, statt einer Shell oder eines
Kommandos:

```bash
# interaktive sftp-Shell über einen eigenen sftp-Kanal
ssh3 -s sftp user@host
```

`sftp` wird gesondert vom interaktiven SFTP-Client bedient, dessen Befehle
`pwd`, `ls`, `cd`, `get`, `put`, `mkdir`, `rm`, `rmdir`, `help`,
`quit`/`exit` sind – also der für eine Sitzung am Prompt nützliche Teil von
`sftp(1)`. Jeder andere Name wird, genau wie in `ssh(1)`, als
Subsystem-Anfrage auf dem Sitzungskanal gesendet; der mitgelieferte
Go-Server antwortet auf eine solche Anfrage mit *not implemented*, ein
freier Name lohnt also nur gegen einen Server, der Subsysteme bedient. Mit
`-t` wird das PTY vor dem Subsystem angefordert.

`-s` belegt den Sitzungskanal und wird deshalb auf Kommandozeilenebene
zusammen mit `-f`, `-N`, `-forward-agent`, `-R` und einem entfernten Kommando
abgelehnt.

### Alternative Konfigurationsdatei (`-F`)

`-F PATH` liest eine andere Benutzerkonfigurationsdatei als `~/.ssh/config`;
ohne `-F` liest der Client wie üblich `~/.ssh/config`. Der Pfad wird
wörtlich verwendet, wie in OpenSSH, ein relativer Pfad bleibt also relativ
zum aktuellen Verzeichnis:

```bash
ssh3 -F ./ci/ssh_config user@host 'uptime'
ssh3 -F /home/deploy/.ssh/config.work user@host
```

Alles aus dem folgenden Abschnitt – `Host`, `Match`, `Include` – wird aus
dieser Datei genauso aufgelöst. Ein unlesbarer Pfad lässt die Verbindung nicht
scheitern: der Lesefehler geht nach stderr und die Konfiguration wird
ignoriert, eine fehlende Datei wird stillschweigend übersprungen.


## Client-Konfiguration (~/.ssh/config)
Neben `HostName`, `Port`, `User` und `IdentityFile` berücksichtigt der Client
pro `Host`-Muster: `ProxyJump` (als ssh3-UDP-Proxy-Jump interpretiert: der
Jump-Host muss ssh3-server ausführen), `UDPProxyJump` (Fork-Erweiterung,
gleiche Semantik), `ForwardAgent` und `ServerAliveInterval` (Sekunden;
stimmt den QUIC-Keepalive ab, Standard 1).

### `Match`-Blöcke
`Match` wird von einem Vor-Parser aufgelöst, der vor dem Lauf des
ssh_config-Decoders nur die für den angefragten Alias zutreffenden Blöcke
abflacht; damit bleiben die „first obtained value wins“-Prioritäten aus
`ssh_config(5)` erhalten. Unterstützte Kriterien: `all`, `final`, `host`,
`originalhost`, `user`, `localuser` und `exec`, mit Negation über `!` und
Glob-Mustern. Konfigurationen ohne jeden `Match`-Block nehmen den
unveränderten schnellen Pfad.

```text
Host example.lan
    User deploy
    Match originalhost web*
        Port 2222
    Match exec "test -f /srv/maintenance"
        ForwardAgent no
```

Zwei ssh3-spezifische Vereinfachungen folgen daraus, dass die Konfiguration
in einem Durchgang angewendet wird und Hostnamen nie kanonisiert werden:
`final` trifft immer zu, `canonical` nie. `host` und `user` werden gegen das
wachsende Ziel ausgewertet, ein von einem früheren zutreffenden Block
gesetztes `HostName` oder `User` ist also auch für spätere `Match`-Blöcke
sichtbar. `exec` läuft unter unix über `sh -c`, unter Windows über `cmd /c`,
und gilt bei Exit-Status 0 als erfüllt.

### `Match` in `Include`-Dateien
`Include` wird vom selben Vor-Parser aufgelöst, rekursiv und *bevor* alles
andere geparst wird – der Inhalt der eingebundenen Datei tritt an die Stelle
der Direktive und setzt den umgebenden `Host`- oder `Match`-Block fort,
genau wie in OpenSSH.

```text
Include ~/.ssh/config.d/*.conf

# ~/.ssh/config.d/web.conf
Match host web*
    Port 2222
    IdentityFile ~/.ssh/id_ed25519_web
```

Bisher ließ jeder über ein `Include` erreichte `Match`-Block den
ssh_config-Decoder scheitern und die gesamte `~/.ssh/config` wurde
verworfen. Nun durchläuft ein eingebundener `Host`- oder `Match`-Block
dieselbe Alias- und `Match`-Filterung wie die Hauptdatei. Unterstützt werden
Glob-Muster in `Include`-Zielen, verschachtelte Includes, ein Schutz gegen
zirkuläre Includes und eine Rekursionstiefe von 16. Ein fehlendes oder
unlesbares Include wird übersprungen, statt den Rest der Konfiguration
ungültig zu machen, und ein `Match`-Parsefehler nennt die eingebundene Datei
sowie die Zeile, aus der er wirklich stammt.

### SSHFP-Hostprüfung (RFC 4255)
Die SSHFP-Engine vergleicht die für einen Host veröffentlichten
DNS-Einträge vom Typ 44 mit dem echten Fingerabdruck des präsentierten
Hostschlüssels. Der Fingerabdruck wird über das **DER-X.509-Zertifikat des
Hosts** gebildet: ssh3 pinnt Zertifikate, keine rohen SSH-Public-Keys. Das
DNS-Wire-Format wird im Projekt selbst aufgebaut und geparst, ein
Drittanbieter-Resolver ist also nicht nötig.

Standardmäßig aus, wie in OpenSSH; eingeschaltet wird die Prüfung mit `-o
VerifyHostKeyDNS=...` oder demselben Schlüssel in `~/.ssh/config`, mit der
üblichen Quellenpräzedenz (`-o` > `~/.ssh/config`, und der Standard bleibt
aus):

```bash
# den Host ablehnen, wenn seine veröffentlichten SSHFP-Einträge nicht zum Schlüssel passen
ssh3 -o VerifyHostKeyDNS=yes user@host

# die Abfrage auf bestimmte Hostschlüssel-Algorithmen beschränken
ssh3 -o VerifyHostKeyDNS=yes:ed25519,rsa user@host

# derselbe Schlüssel pro Host in ~/.ssh/config
```

```text
Host example.lan
    VerifyHostKeyDNS yes:ed25519
```

Akzeptierte Werte:

| Wert | Bedeutung |
| --- | --- |
| `no` (auch `false`, `off`, leer) | gar keine Abfrage – der Standard, also kein DNS-Verkehr und keine zusätzliche Latenz |
| `ask` | die Einträge prüfen, wenn sie veröffentlicht sind |
| `yes` (auch `true`, `on`) | die Einträge prüfen und eine Übereinstimmung verlangen |
| `yes:algo[,algo...]` | wie oben, beschränkt auf die genannten Hostschlüssel-Algorithmen |

Der Vergleich ist case-insensitiv, umgebende Leerraum wird ignoriert. Die
Algorithmusliste akzeptiert die kurzen und die vollen Public-Key-Namen – `rsa`,
`ssh-rsa`, `dsa`, `ssh-dss`, `ssh-dsa`, `ecdsa`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `sk-ecdsa-sha2-nistp256`,
`ed25519`, `ssh-ed25519` – sowie die Digest-Namen `sha1` und `sha256`, die
OpenSSH aus Kompatibilitätsgründen ebenfalls akzeptiert. Ein Hostschlüssel
außerhalb der Liste ist von der Anfrage schlicht nicht abgedeckt, und für ihn
wird die Abfrage übersprungen. Ein unbekannter Wert oder Algorithmus wird vor
dem Verbindungsaufbau abgelehnt, mit demselben *„Bad configuration option"* wie
jede andere fehlerhafte `-o`-Angabe.

Die Politik ist bewusst vorsichtig:

- **Nur eine Abweichung lehnt den Host ab** – Einträge wurden veröffentlicht,
  wurden geholt, und keiner passt zum präsentierten Schlüssel. NXDOMAIN, eine
  leere Antwort, ein abgeschnittenes Datagramm, ein Timeout, ein nicht
  verfügbarer Resolver und Netzwerkfehler sind alles *weiche Überspringungen*:
  die Verbindung läuft allein nach der known_hosts-Entscheidung weiter. Das ist
  ein strikt zusätzliches Signal über die known_hosts-Prüfung hinaus, niemals
  deren Ersatz.
- `ask` fragt nicht nach. Eine Abweichung unter `ask` lehnt ab, mit einer
  Warnung, die die Option nennt, mit der sie sich übersteuern ließe.
- Mit `-o StrictHostKeyChecking=no` warnt eine Abweichung nur, und die
  Verbindung läuft weiter – genau wie die Prüfung des gepinnten Zertifikats bei
  einem geänderten Zertifikat.
- Der Austausch ist standardmäßig auf **2 s** begrenzt, die konfigurierten
  DNS-Server werden der Reihe nach abgefragt.
- Die Abfrage läuft direkt nach dem Verbindungsaufbau, auf demselben
  Zertifikat, das die known_hosts-Prüfung verwendet, und fragt den blanken
  DNS-Namen ab (`user@` und `:port` haben keine DNS-Bedeutung). `-insecure`
  überspringt die Hostprüfung vollständig, also auch SSHFP.
- Unter Windows liegt die Resolver-Konfiguration in der Registry statt in
  `/etc/resolv.conf`, die Server werden daher über `GetAdaptersAddresses` aus
  den lokalen Adaptern gelesen. Liefert diese Aufzählung nichts, ist die
  Abfrage eine weiche Überspringung und kein Fehler.
- Die Eintrags-Algorithmen RSA, DSA, ECDSA und Ed25519 werden erkannt;
  SHA-1- und SHA-256-Fingerabdrücke werden beide berechnet. RSA-, ECDSA- und
  Ed25519-Hostschlüssel werden dagegen geprüft.

Die Prüfung liegt im unveröffentlichten Baum, für einen End-to-End-Durchlauf
werden also Client und Server aus dieser Quelle gebaut.


## Authentifizierung
### Public Key
Rust-Client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --identity ~/.ssh/id_ed25519 \
  https://127.0.0.1:4433/ssh3-term
```

Der Server liest `~/.ssh3/authorized_identities` oder die Standarddatei `~/.ssh/authorized_keys` des Zielbenutzers.

### SSH-Agent
Rust-Client:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  https://127.0.0.1:4433/ssh3-term
```

Lokalen Agent in die Remote-Sitzung weiterleiten:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --agent \
  --forward-agent \
  https://127.0.0.1:4433/ssh3-term
```

### Passwort
Go-Server (amd64-Release-Pakete liefern das einkompilierte, standardmäßig aktivierte Backend; `SSH3_ENABLE_PASSWORD_LOGIN=0` schaltet es ab). Aufruf mit Passwort:

```bash
ssh3-server ... -enable-password-login
```

oder beim systemd-Dienst in `/etc/ssh3/ssh3-server.env`:

```bash
SSH3_ENABLE_PASSWORD_LOGIN=1
```

gefolgt von `sudo systemctl restart ssh3-server`. Verbindung mit dem Go-Client:

```bash
ssh3 -use-password benutzer@my-server.example.org/ssh3-term
```

Der Go-Client fragt das Passwort interaktiv im Terminal ab; es wird nie als Kommandozeilen-Argument übergeben.

Rust-Äquivalent (Server/Client):

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

Hinweis: arm-Server-Builds sind mit `-tags disable_password_auth` kompiliert (nur Schlüssel); dort existiert der Passwort-Pfad nur in eigenen Builds.

### OpenID Connect
OIDC im Rust-Client läuft über Flags statt einer Konfigurationsdatei:

```bash
cargo run -p ssh3-client -- \
  --insecure \
  --user "$USER" \
  --use-oidc https://issuer.example \
  --oidc-client-id your-client-id \
  --oidc-client-secret-file /path/to/oidc-client-secret.txt \
  https://127.0.0.1:4433/ssh3-term
```

Autorisierte OIDC-Identitäten können in `authorized_identities` neben Public Keys stehen:

```text
oidc <client_id> <issuer_url> <email>
```

## Tests
Der Rust-Workspace ist der primäre Verifikationsweg dieses Repositories.

Volle Rust-Suite:

```bash
cargo test
```

Die tiefste Rust/Go-Interop-Matrix:

```bash
cargo test -p ssh3-client
```

Die Interop-Suite lässt echte Rust- und Go-Binaries gegeneinander laufen:

- Exec- und Shell-Sitzungen
- PTY-Zuteilung, Resize und Signal-Forwarding
- Public-Key-, Passwort- und OIDC-Authentifizierung
- SSH-Agent-Authentifizierung und Agent-Forwarding
- TCP- und UDP-Forwarding

Bei direkten Go-Befehlen reichen die vendored Abhängigkeiten aus:

```bash
go build ./...
```

## Bekannte Lücken
- Der Rust-Server ist heute bewusst minimal: nur selbstsignierte Zertifikate, kein geheimer URL-Pfad, keine Automatisierung öffentlicher Zertifikate.
- Die Rust-CLI exponiert noch keine TCP-/UDP-Forwarding- oder Proxy-Jump-Flags, obwohl die Runtime implementiert und getestet ist.
- Rückwärtige Weiterleitung (`-R`) und dynamisches SOCKS-Forwarding (`-D`) gibt es nur im Go-Client und im Go-Server, und beide sind neuer als das letzte Release: ein Server, der sie nicht kennt, lehnt die Anfrage mit einem expliziten „not supported"-Fehler ab.
- Der Windows-Client hat kein SSH-Agent-Forwarding und leitet keine Fenstergrößenänderungen weiter (in Go gibt es dort kein `SIGWINCH`); die erste Verbindung zu einem selbstsignierten Server erfordert ein in `known_hosts` hinterlegtes Zertifikat, da die interaktive TOFU-Abfrage ein Unix-typisches tty braucht.
- Der Go-Server implementiert keine Subsystem-Anfragen, heute ist daher nur das Subsystem `sftp` nutzbar (`ssh3 -s sftp`).

## Sicherheit
SSH3 ist vielversprechend, aber das Projekt braucht noch erhebliche Prüfung, bevor man ihm in der Produktion vertrauen kann. Die Protokolloberfläche kombiniert TLS 1.3, QUIC, HTTP-Autorisierung und SSH-artige Kanalsemantik — der richtige Maßstab ist eine lange Phase von Reviews und Interop-Härtung, nicht „läuft auf meiner Maschine“.

Nutzen Sie es in Labors, CI, privaten Umgebungen und Interop-Experimenten. Verlassen Sie sich noch nicht darauf als fertigen OpenSSH-Ersatz für die Produktion.

## Lizenz
Das Projekt steht unter der [Apache License 2.0](LICENSE), geerbt vom Upstream-Projekt [francoismichel/ssh3](https://github.com/francoismichel/ssh3). Die Änderungen dieses Forks, einschließlich der Dokumentation, werden zu denselben Apache-2.0-Bedingungen vertrieben.
