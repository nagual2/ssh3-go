package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	ssh3 "github.com/francoismichel/ssh3"
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/server"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/server_auth"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"
	"github.com/pkg/sftp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const defaultURLPath = "/ssh3-term"

func main() {
	os.Exit(run())
}

func run() int {
	var bindAddr string
	var urlPath string
	var username string
	var authorizedIdentityPath string
	var certPath string
	var keyPath string

	flag.StringVar(&bindAddr, "bind", "127.0.0.1:4433", "UDP bind address")
	flag.StringVar(&urlPath, "url-path", defaultURLPath, "SSH3 URL path")
	flag.StringVar(&username, "user", "", "session username")
	flag.StringVar(&authorizedIdentityPath, "authorized-identity", "", "authorized identities file")
	flag.StringVar(&certPath, "cert", "", "certificate path")
	flag.StringVar(&keyPath, "key", "", "private key path")
	flag.Parse()

	if username == "" || authorizedIdentityPath == "" || certPath == "" || keyPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags: --user, --authorized-identity, --cert, and --key")
		return 2
	}

	util.ConfigureLogger("error")

	if err := ensureCertificate(certPath, keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "could not prepare certificate: %s\n", err)
		return 1
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load certificate: %s\n", err)
		return 1
	}

	baseTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}
	server := http3.Server{
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			Allow0RTT: true,
		},
		TLSConfig: http3.ConfigureTLSConfig(baseTLSConfig),
	}

	ssh3Server := ssh3.NewServer(30_000, 10, &server, func(authenticatedUsername string, conv *ssh3.Conversation) error {
		return handleConversation(authenticatedUsername, conv)
	})
	authenticatedHandler := ssh3Server.GetHTTPHandlerFunc(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		defer w.(http.Flusher).Flush()

		peerVersion, err := ssh3.ParseVersionString(r.UserAgent())
		if err != nil {
			fmt.Fprintf(os.Stderr, "unauthorized/forbidden: bad user-agent %q: %s\n", r.UserAgent(), err)
			http.Error(w, "unsupported SSH3 user-agent", http.StatusForbidden)
			return
		}
		if !ssh3.IsVersionSupported(peerVersion) {
			fmt.Fprintf(os.Stderr, "unauthorized/forbidden: unsupported version %q\n", r.UserAgent())
			http.Error(w, "unsupported SSH3 version", http.StatusForbidden)
			return
		}

		// quic-go v0.63 removed http3.Hijacker: the QUIC connection is retrieved
		// from the request context, where the http3.Server.ConnContext hook set
		// up by ssh3.NewServer put it
		qconn, ok := ssh3.QuicConnFromContext(r.Context())
		if !ok {
			http.Error(w, "http3 conn unavailable", http.StatusInternalServerError)
			return
		}
		if !qconn.ConnectionState().TLS.HandshakeComplete {
			fmt.Fprintln(os.Stderr, "unauthorized: TLS handshake incomplete")
			w.WriteHeader(http.StatusTooEarly)
			return
		}

		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "http3 stream unavailable", http.StatusInternalServerError)
			return
		}
		conv, err := ssh3.NewServerConversation(
			// derive from the QUIC connection so the conversation dies with it
			// (same rationale as server_auth.HandleAuths)
			qconn.Context(),
			streamer.HTTPStream(),
			qconn,
			qconn,
			30_000,
			peerVersion,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unauthorized: could not create conversation: %s\n", err)
			http.Error(w, "could not create SSH3 conversation", http.StatusInternalServerError)
			return
		}

		requestedUsername := requestUsername(r, username)
		if requestedUsername == "" {
			fmt.Fprintln(os.Stderr, "unauthorized: missing username")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sessionUser := currentSessionUser(requestedUsername)

		identities, err := loadAuthorizedIdentities(sessionUser, authorizedIdentityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load authorized identities: %s\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		conversationID := conv.ConversationID()
		base64ConversationID := base64.StdEncoding.EncodeToString(conversationID[:])
		for _, identity := range identities {
			if identity.Verify(r, base64ConversationID) {
				authenticatedHandler(requestedUsername, conv, w, r)
				return
			}
		}

		bearerToken, ok := server_auth.ParseBearerAuth(r.Header.Get("Authorization"))
		if ok {
			for _, identity := range identities {
				if identity.Verify(util.JWTTokenString{Token: bearerToken}, base64ConversationID) {
					authenticatedHandler(requestedUsername, conv, w, r)
					return
				}
			}
		}

		fmt.Fprintf(
			os.Stderr,
			"unauthorized: user=%s identities=%d authorization_present=%t\n",
			requestedUsername,
			len(identities),
			r.Header.Get("Authorization") != "",
		)
		w.WriteHeader(http.StatusUnauthorized)
	})
	server.Handler = mux

	// quic-go v0.63 removed StreamHijacker: accept QUIC connections here so the
	// ssh3 server can drive the HTTP/3 accept loops and dispatch SSH3 channel
	// streams itself
	packetConn, err := net.ListenPacket("udp", bindAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not bind %s: %s\n", bindAddr, err)
		return 1
	}
	defer packetConn.Close()

	listener, err := quic.ListenEarly(packetConn, server.TLSConfig, server.QUICConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "go interop server failed: %s\n", err)
		return 1
	}

	fmt.Printf("READY %s\n", listener.Addr().String())
	for {
		qconn, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "go interop server failed: %s\n", err)
			return 1
		}
		go func() {
			hconn, err := server.NewRawServerConn(qconn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "go interop server failed: %s\n", err)
				qconn.CloseWithError(quic.ApplicationErrorCode(0), "internal error")
				return
			}
			ssh3Server.ServeQUICConn(context.Background(), qconn, hconn)
		}()
	}
}

func requestUsername(r *http.Request, fallback string) string {
	if username := r.Header.Get("x-ssh3-user"); strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username)
	}
	if username := r.URL.User.Username(); username != "" {
		return username
	}
	if username := r.URL.Query().Get("user"); strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username)
	}
	return fallback
}

func loadAuthorizedIdentities(
	user *unix_util.User,
	path string,
) ([]server_auth.IdentityVerifier, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return server_auth.ParseAuthorizedIdentitiesFile(user, file)
}

func ensureCertificate(certPath, keyPath string) error {
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	if certExists && keyExists {
		return nil
	}
	if certExists != keyExists {
		return fmt.Errorf("certificate and key must either both exist or both be absent")
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return err
	}

	pubkey, privkey, err := util.GenerateKey()
	if err != nil {
		return err
	}
	cert, err := util.GenerateCert(privkey)
	if err != nil {
		return err
	}
	cert.DNSNames = append(cert.DNSNames, "localhost")
	if ip := net.ParseIP("127.0.0.1"); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	}
	return util.DumpCertAndKeyToFiles(cert, pubkey, privkey, certPath, keyPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func handleConversation(authenticatedUsername string, conv *ssh3.Conversation) error {
	sessionUser := currentSessionUser(authenticatedUsername)

	for {
		channel, err := conv.AcceptChannel(conv.Context())
		if err != nil {
			return err
		}
		go handleChannel(sessionUser, conv, channel)
	}
}

func currentSessionUser(username string) *unix_util.User {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return &unix_util.User{
		Username: username,
		Uid:      uint64(os.Getuid()),
		Gid:      uint64(os.Getgid()),
		Dir:      homeDir,
		Shell:    shell,
	}
}

func handleChannel(user *unix_util.User, conv *ssh3.Conversation, channel ssh3.Channel) {
	switch channel.ChannelType() {
	case sftpChannelType:
		serveSFTP(user, channel)
		return
	case "session":
	default:
		_ = writeStderr(channel, fmt.Sprintf("unsupported channel type %s\n", channel.ChannelType()))
		channel.Close()
		return
	}

	// session channel: messages are consumed until an exec request arrives;
	// LARVAL-state "forward-agent" data arms agent forwarding first (same
	// wire convention as the real server).
	var agentSocketPath string
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil || genericMessage == nil {
			return
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			if message.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE || message.Data != agentForwardTrigger {
				_ = writeStderr(channel, "unexpected data on session channel\n")
				return
			}
			if agentSocketPath != "" {
				_ = writeStderr(channel, "agent forwarding already active\n")
				return
			}
			agentSocketPath, err = openAgentSocketAndForwardAgent(conv)
			if err != nil {
				_ = writeStderr(channel, fmt.Sprintf("could not start agent forwarding: %s\n", err))
				return
			}
		case *ssh3Messages.ChannelRequestMessage:
			execRequest, ok := message.ChannelRequest.(*ssh3Messages.ExecRequest)
			if !ok {
				_ = writeStderr(channel, "unsupported request\n")
				return
			}
			if err := runExec(user, channel, execRequest.Command, agentSocketPath); err != nil {
				_ = writeStderr(channel, fmt.Sprintf("%s\n", err))
			}
			return
		default:
			_ = writeStderr(channel, "unexpected message on session channel\n")
			return
		}
	}
}

// --- sftp subsystem ---

const sftpChannelType = "sftp"

// SFTP v3 open flags the write path cares about (private in pkg/sftp;
// SSH_FXF_* from the wire spec).
const (
	sftpFlagCreate = 0x00000008
	sftpFlagTrunc  = 0x00000010
)

// sftpJail serves pkg/sftp requests inside the session user's home directory.
// Every client path goes through resolveJailed so nothing escapes the jail,
// and freshly created inodes are chowned back to the user (a no-op unless the
// harness runs as root; kept for parity with the real server, which may).
type sftpJail struct {
	user *unix_util.User
	root string
}

func newSFTPJail(user *unix_util.User) (*sftpJail, error) {
	if user.Dir == "" {
		return nil, fmt.Errorf("user %s has no home directory", user.Username)
	}
	absRoot, err := filepath.Abs(user.Dir)
	if err != nil {
		return nil, err
	}
	return &sftpJail{user: user, root: absRoot}, nil
}

// serveSFTP runs for the whole lifetime of an "sftp" channel; handleChannel
// already spawned it as its own goroutine.
func serveSFTP(user *unix_util.User, channel ssh3.Channel) {
	jail, err := newSFTPJail(user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sftp subsystem: %s\n", err)
		channel.Close()
		return
	}
	rwc := ssh3.NewChannelReadWriteCloser(channel)
	server := sftp.NewRequestServer(rwc, sftp.Handlers{
		FileGet:  jail,
		FilePut:  jail,
		FileCmd:  jail,
		FileList: jail,
	})
	fmt.Printf("SFTP-SUBSYSTEM-READY %s\n", jail.root)
	defer func() {
		if err := server.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "sftp subsystem: server close: %s\n", err)
		}
		channel.Close()
	}()
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "sftp subsystem ended: %s\n", err)
	}
}

// resolveJailed maps a client-visible path into the jail, rejecting escapes
// (compact port of cmd/sftp_subsystem.go). Jail-relative paths ("docs/f",
// "/docs/f") resolve under the home directory; server-absolute paths already
// living inside the jail are honored as-is; anything else is an error.
func (j *sftpJail) resolveJailed(clientPath string) (string, error) {
	trimmed := strings.TrimSpace(clientPath)
	if trimmed == "" {
		trimmed = "/"
	}
	if filepath.IsAbs(filepath.FromSlash(trimmed)) {
		abs := filepath.Clean(filepath.FromSlash(trimmed))
		if abs == j.root || strings.HasPrefix(abs, j.root+string(filepath.Separator)) {
			return abs, nil
		}
	}
	clean := path.Clean("/" + trimmed)
	full := filepath.Join(j.root, filepath.FromSlash(clean))
	if full != j.root && !strings.HasPrefix(full, j.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the home directory", clientPath)
	}
	return full, nil
}

// RealPath implements sftp.RealPathFileLister: the canonical client-visible
// path of a jail-resolved file.
func (j *sftpJail) RealPath(clientPath string) (string, error) {
	return j.resolveJailed(clientPath)
}

// chownToUser gives freshly created inodes back to the session user; errors
// are swallowed: when not running as root the ownership is already correct.
func (j *sftpJail) chownToUser(name string) {
	_ = os.Chown(name, int(j.user.Uid), int(j.user.Gid))
}

// chownToUserRoot fixes ownership of every directory level MkdirAll created.
func (j *sftpJail) chownToUserRoot(name string) {
	for current := name; current != j.root && strings.HasPrefix(current, j.root+string(filepath.Separator)); current = filepath.Dir(current) {
		j.chownToUser(current)
	}
}

func (j *sftpJail) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	name, err := j.resolveJailed(request.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(name)
}

func (j *sftpJail) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	name, err := j.resolveJailed(request.Filepath)
	if err != nil {
		return nil, err
	}
	flags := os.O_WRONLY
	if request.Flags&sftpFlagCreate != 0 {
		flags |= os.O_CREATE
	}
	if request.Flags&sftpFlagTrunc != 0 {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(name, flags, 0o644)
	if err != nil {
		return nil, err
	}
	if flags&os.O_CREATE != 0 {
		j.chownToUser(name)
	}
	return file, nil
}

func (j *sftpJail) Filecmd(request *sftp.Request) error {
	switch request.Method {
	case "Mkdir":
		name, err := j.resolveJailed(request.Filepath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(name, 0o755); err != nil {
			return err
		}
		j.chownToUserRoot(name)
		return nil
	case "Rename":
		oldName, err := j.resolveJailed(request.Filepath)
		if err != nil {
			return err
		}
		newName, err := j.resolveJailed(request.Target)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(newName); err == nil {
			return os.ErrExist
		}
		return os.Rename(oldName, newName)
	case "Remove", "Rmdir":
		name, err := j.resolveJailed(request.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(name)
	default:
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (j *sftpJail) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	switch request.Method {
	case "List":
		name, err := j.resolveJailed(request.Filepath)
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(name)
		if err != nil {
			return nil, err
		}
		infos := make([]fs.FileInfo, 0, len(entries))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			infos = append(infos, namedFileInfo{FileInfo: info, name: entry.Name()})
		}
		return &sftpListerAt{infos: infos}, nil
	case "Stat":
		name, err := j.resolveJailed(request.Filepath)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		return &sftpListerAt{infos: []fs.FileInfo{info}}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

// sftpListerAt serves directory entries one window at a time, as pkg/sftp expects.
type sftpListerAt struct {
	infos []fs.FileInfo
}

func (l *sftpListerAt) ListAt(buf []fs.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.infos)) {
		return 0, io.EOF
	}
	n := copy(buf, l.infos[offset:])
	if offset+int64(n) < int64(len(l.infos)) {
		return n, nil
	}
	return n, io.EOF
}

// namedFileInfo renames a FileInfo so List reports the entry name, not the
// one from os.Stat of the parent.
type namedFileInfo struct {
	fs.FileInfo
	name string
}

func (f namedFileInfo) Name() string { return f.name }

// --- agent forwarding ---

// agentForwardTrigger is the LARVAL-state data payload a client sends on a
// session channel to request ssh-agent forwarding (same wire convention as
// the real server).
const agentForwardTrigger = "forward-agent"

// openAgentSocketAndForwardAgent listens on a fresh UDS (os.MkdirTemp +
// agent.<pid>, like unix_util.NewUnixSocketPath) and forwards every accepted
// connection to a server-initiated "agent-connection" channel; the returned
// path goes into the child's SSH_AUTH_SOCK. The socket is chowned to the
// session user by the caller's own uid, so no explicit chown is needed.
func openAgentSocketAndForwardAgent(conv *ssh3.Conversation) (string, error) {
	sockPath, err := unix_util.NewUnixSocketPath()
	if err != nil {
		return "", err
	}
	sockDir := path.Dir(sockPath)
	ctx, cancel := context.WithCancelCause(conv.Context())
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(ctx, "unix", sockPath)
	if err != nil {
		cancel(err)
		return "", err
	}
	fmt.Printf("AGENT-SOCKET-READY %s\n", sockPath)
	go func() {
		defer cancel(nil)
		defer listener.Close()
		defer os.Remove(sockPath)
		defer os.Remove(sockDir)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go bridgeAgentSocketConn(conn, conv)
		}
	}()
	return sockPath, nil
}

// bridgeAgentSocketConn pumps one UDS connection over a server-initiated
// "agent-connection" channel (compact port of handleAuthAgentSocketConn).
func bridgeAgentSocketConn(conn net.Conn, conv *ssh3.Conversation) {
	defer conn.Close()
	channel, err := conv.OpenChannel("agent-connection", 30000, 10)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent forwarding: could not open channel: %s\n", err)
		return
	}
	defer channel.Close()
	go func() {
		defer channel.Close()
		buf := make([]byte, channel.MaxPacketSize())
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := channel.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
				return
			}
		}
	}()
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			return
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			if _, err := conn.Write([]byte(message.Data)); err != nil {
				return
			}
		default:
			fmt.Fprintf(os.Stderr, "agent forwarding: unhandled message type %T\n", message)
			return
		}
	}
}

func runExec(user *unix_util.User, channel ssh3.Channel, command, agentSocketPath string) error {
	shell := user.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell, "-c", command)
	cmd.Dir = user.Dir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", user.Dir),
		fmt.Sprintf("USER=%s", user.Username),
		fmt.Sprintf("LOGNAME=%s", user.Username),
		fmt.Sprintf("SHELL=%s", shell),
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	)
	if agentSocketPath != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SSH_AUTH_SOCK=%s", agentSocketPath))
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = stdin.Close()

	readResult := func(reader io.Reader, dataType ssh3Messages.SSHDataType) <-chan error {
		done := make(chan error, 1)
		go func() {
			done <- pumpOutput(channel, reader, dataType)
			close(done)
		}()
		return done
	}
	stdoutDone := readResult(stdout, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	stderrDone := readResult(stderr, ssh3Messages.SSH_EXTENDED_DATA_STDERR)

	// All pipe readers have drained: only now is Wait safe. os/exec closes
	// the pipe readers when Wait returns, so calling it earlier races the
	// output pumps: the losing pump reads "file already closed" instead of
	// EOF, and the exec then skips the exit status (the client hangs). The
	// product server carries the same posture ("only now is Wait safe").
	stdoutErr := <-stdoutDone
	stderrErr := <-stderrDone

	exitStatus := 1
	waitErr := cmd.Wait()
	if waitErr == nil {
		if status := cmd.ProcessState.ExitCode(); status >= 0 {
			exitStatus = status
		}
	} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if status := exitErr.ExitCode(); status >= 0 {
			exitStatus = status
		}
	} else {
		return waitErr
	}

	if stdoutErr != nil {
		return stdoutErr
	}
	if stderrErr != nil {
		return stderrErr
	}

	return channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
		WantReply: false,
		ChannelRequest: &ssh3Messages.ExitStatusRequest{
			ExitStatus: uint64(exitStatus),
		},
	})
}

func pumpOutput(channel ssh3.Channel, reader io.Reader, dataType ssh3Messages.SSHDataType) error {
	buf := make([]byte, int(channel.MaxPacketSize()))
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, writeErr := channel.WriteData(buf[:n], dataType); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func writeStderr(channel ssh3.Channel, message string) error {
	_, err := channel.WriteData([]byte(message), ssh3Messages.SSH_EXTENDED_DATA_STDERR)
	return err
}
