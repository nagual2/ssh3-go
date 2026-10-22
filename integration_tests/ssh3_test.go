package integration_tests

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var ssh3Path string
var ssh3ServerPath string

const DEFAULT_URL_PATH = "/ssh3-tests"
const DEFAULT_PROXY_URL_PATH = "/ssh3-tests-proxy"

var serverCommand *exec.Cmd
var serverSessions map[string]*Session = make(map[string]*Session) // bind address to session
var proxyServerCommand *exec.Cmd
var proxyServerSession *Session
var rsaPrivKeyPath string
var ed25519PrivKeyPath string
var ecdsaPrivKeyPath string
var attackerPrivKeyPath string
var username string
var ecdsaUsername string

const serverBind = "127.0.0.1:4433"
const proxyServerBind = "127.0.0.1:4444"

// The timeouts the specs wait for. The gomega default is one second, which is
// too tight for a client that has to dial QUIC, authenticate and only then
// opens the forward: on a loaded machine the wait expires before the client
// is even listening, and the spec fails for a timing reason instead of a real
// one.
const (
	clientStartupTimeout = 20 * time.Second
	commandTimeout       = 20 * time.Second
	forwardReadyTimeout  = 20 * time.Second
)

// transferClientArgs builds the client command line of a file transfer.
//
// The transfer mode lives under the -transfer long form since the CLI-parity
// wave (CTO_TASK §7c row 1): -f is the ssh(1) background flag now, so the
// retired "-f SRC DST" transfer form must not come back to the harness - the
// client would background itself and the transfer would silently never
// happen.
func transferClientArgs(privKeyPath string, operands ...string) []string {
	args := []string{"-v", "-insecure", "-i", privKeyPath, "-transfer"}
	return append(args, operands...)
}

func IPv6LoopbackAvailable(addrs []net.Addr) bool {
	for _, addr := range addrs {
		Expect(addr).To(BeAssignableToTypeOf(&net.IPNet{}))
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.To16() != nil && ip.IsLoopback() {
			// we found ::1, we can start the test
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../cmd/ssh3/main.go")
	Expect(err).ToNot(HaveOccurred())
	if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") == "1" {
		// Tests implying a server will only work on Linux
		// (the server currently only builds on Linux)
		// and the server needs root priviledges, so we only
		// run them is they are enabled explicitly.
		ssh3ServerPath, err = BuildWithEnvironment("../cmd/ssh3-server/main.go", []string{fmt.Sprintf("CGO_ENABLED=%s", os.Getenv("CGO_ENABLED"))})
		Expect(err).ToNot(HaveOccurred())
		serverCommand = exec.Command(ssh3ServerPath,
			"-bind", serverBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		serverCommand.Env = append(serverCommand.Env, "SSH3_LOG_LEVEL=debug")
		session, err := Start(serverCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[serverBind] = session

		// Note: the retro-compatibility probes against the v0.1.5 servers
		// (v0.1.5-rc1/rc5) were dropped here: the client wire has moved on
		// since v0.1.5 (the pty request now carries the RFC 4254 terminal
		// modes, CTO_TASK §7b.1) and the client detects a truncated transfer
		// (CTO_TASK §4 bug 3) - both unknown to the v0.1.5 server, which
		// cancels the conversation instead of running the command. Keeping
		// the probes would keep the linux integration job red for a
		// compatibility that the fork does not provide anymore.

		proxyServerCommand = exec.Command(ssh3ServerPath,
			"-bind", proxyServerBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_PROXY_URL_PATH,
			// the jump host forwards the tunneled QUIC packets as SSH3
			// datagrams: its datagram budget is the initial packet size
			// minus the QUIC packet overhead, so it needs the maximum packet
			// size to carry the packets of the tunneled connection
			"-initial-packet-size", "1452",
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		proxyServerCommand.Env = append(proxyServerCommand.Env, "SSH3_LOG_LEVEL=debug")
		proxyServerSession, err = Start(proxyServerCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[proxyServerBind] = proxyServerSession

		rsaPrivKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		ed25519PrivKeyPath = os.Getenv("TESTUSER_ED25519_PRIVKEY")
		ecdsaPrivKeyPath = os.Getenv("TESTUSER_ECDSA_PRIVKEY")
		attackerPrivKeyPath = os.Getenv("ATTACKER_PRIVKEY")
		username = os.Getenv("TESTUSER_USERNAME")
		ecdsaUsername = os.Getenv("ECDSATESTUSER_USERNAME")
		Expect(fileExists(rsaPrivKeyPath)).To(BeTrue())
		Expect(fileExists(attackerPrivKeyPath)).To(BeTrue())
		err = os.WriteFile(fmt.Sprintf("/home/%s/.profile", username), []byte("echo 'hello from .profile'"), 0777)
		Expect(err).ToNot(HaveOccurred())
	}
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	for _, serverSession := range serverSessions {
		serverSession.Terminate()
	}
})

var _ = Describe("Testing the ssh3 cli", func() {

	Context("Usage", func() {
		It("Displays the help", func() {
			command := exec.Command(ssh3Path, "-h")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session, commandTimeout).Should(Exit(0))
			Expect(session.Err.Contents()).To(ContainSubstring("Usage of"))
		})

		It("Documents the ssh2-canonical launch keys", func() {
			// the CLI-parity wave (CTO_TASK §7c) made the ssh(1)/sshd(8)
			// forms primary: the usage must advertise them, the transfer mode
			// must live under -transfer (-f is the ssh(1) background flag now)
			command := exec.Command(ssh3Path, "-h")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session, commandTimeout).Should(Exit(0))
			usage := string(session.Err.Contents())
			for _, flagName := range []string{"-i", "-V", "-A", "-J", "-L", "-M", "-S", "-q", "-4", "-6", "-transfer"} {
				Expect(usage).To(ContainSubstring(flagName), "the usage does not advertise %s", flagName)
			}
		})
	})

	Context("With running server", func() {
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
			Consistently(serverSessions[serverBind], "200ms").ShouldNot(Exit())
		})

		Context("Insecure", func() {
			var clientArgs []string
			getClientArgsWithBind := func(privKeyPath string, bind string, additionalArgs ...string) []string {
				// -i is the ssh(1)-canonical identity flag; -privkey stays the
				// deprecated alias of the fork and is covered by its own spec
				args := []string{
					"-v",
					"-insecure",
					"-i", privKeyPath,
				}
				args = append(args, additionalArgs...)
				args = append(args, fmt.Sprintf("%s@%s%s", username, bind, DEFAULT_URL_PATH))
				return args
			}
			getClientArgs := func(privKeyPath string, additionalArgs ...string) []string {
				return getClientArgsWithBind(privKeyPath, serverBind, additionalArgs...)
			}

			Context("Client behaviour", func() {
				It("Should connect using an RSA privkey", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))
					Eventually(session, commandTimeout).Should(Say("Hello, World!\n"))
				})

				It("Should connect using the deprecated -privkey alias", func() {
					// the fork's own flag stays a working alias of the
					// ssh(1)-canonical -i (CTO_TASK §7c row 2)
					clientArgs = append([]string{"-v", "-insecure", "-privkey", rsaPrivKeyPath},
						fmt.Sprintf("%s@%s%s", username, serverBind, DEFAULT_URL_PATH), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))
					Eventually(session, commandTimeout).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an RSA privkey through proxy jump", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH)), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))
					Eventually(session, commandTimeout).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an ed25519 privkey", func() {
					clientArgs = append(getClientArgs(ed25519PrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))
					Eventually(session, commandTimeout).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an ecdsa privkey", func() {
					// the ecdsa identity is checked against another user: the
					// ecdsa test user only carries the ecdsa key
					savedUsername := username
					username = ecdsaUsername
					clientArgs = append(getClientArgs(ecdsaPrivKeyPath), "echo", "Hello, World!")
					username = savedUsername
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))
					Eventually(session, commandTimeout).Should(Say("Hello, World!\n"))
				})

				It("Should return the correct exit status", func() {
					clientArgs0 := append(getClientArgs(rsaPrivKeyPath), "exit", "0")
					clientArgs1 := append(getClientArgs(rsaPrivKeyPath), "exit", "1")
					clientArgs255 := append(getClientArgs(rsaPrivKeyPath), "exit", "255")
					clientArgsMinus1 := append(getClientArgs(rsaPrivKeyPath), "exit", "-1")

					command0 := exec.Command(ssh3Path, clientArgs0...)
					session, err := Start(command0, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))

					command1 := exec.Command(ssh3Path, clientArgs1...)
					session, err = Start(command1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(1))

					command255 := exec.Command(ssh3Path, clientArgs255...)
					session, err = Start(command255, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(255))

					commandMinus1 := exec.Command(ssh3Path, clientArgsMinus1...)
					session, err = Start(commandMinus1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(255))
				})

				It("Should signal EOF to the remote command when the local stdin is exhausted", func() {
					// Once the local stdin reaches EOF, the client must half-close the
					// send side of the session channel (QUIC FIN) so that the remote
					// command sees the end of its input; otherwise a remote command
					// reading until EOF (e.g. `cat > file`) never terminates.
					const payloadSize = 8 * 1024 * 1024
					payload := make([]byte, payloadSize)
					_, err := rand.Read(payload)
					Expect(err).ToNot(HaveOccurred())
					expectedHash := sha256.Sum256(payload)

					remoteOutPath := path.Join(os.TempDir(), fmt.Sprintf("ssh3-stdin-eof-%d.bin", os.Getpid()))
					os.Remove(remoteOutPath)
					defer os.Remove(remoteOutPath)

					clientArgs = append(getClientArgs(rsaPrivKeyPath), "cat", ">", remoteOutPath)
					command := exec.Command(ssh3Path, clientArgs...)
					command.Stdin = bytes.NewReader(payload)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())

					// the client must terminate by itself once its stdin is exhausted
					Eventually(session, "10s").Should(Exit(0))

					remoteOut, err := os.ReadFile(remoteOutPath)
					Expect(err).ToNot(HaveOccurred())
					Expect(remoteOut).To(HaveLen(payloadSize))
					Expect(sha256.Sum256(remoteOut)).To(Equal(expectedHash))
				})

				It("Should transfer large exec output byte-exact", func() {
					// regression: exec stdout used to lose its tail when the
					// server tore the conversation down before the pipe drain
					// finished, and used to carry a stray trailing CR
					const payloadSize = 8 * 1024 * 1024
					payload := make([]byte, payloadSize)
					_, err := rand.Read(payload)
					Expect(err).ToNot(HaveOccurred())
					expectedHash := sha256.Sum256(payload)

					// /tmp is readable and writable for both the suite and the
					// server process regardless of the session user's home
					remoteFile := path.Join("/tmp", fmt.Sprintf("fx-exec-out-%d.bin", os.Getpid()))
					Expect(os.WriteFile(remoteFile, payload, 0o644)).To(Succeed())
					defer os.Remove(remoteFile)

					clientArgs = append(getClientArgs(rsaPrivKeyPath), "cat", remoteFile)
					command := exec.Command(ssh3Path, clientArgs...)
					output, err := command.Output()
					Expect(err).ToNot(HaveOccurred())
					Expect(output).To(HaveLen(payloadSize))
					Expect(sha256.Sum256(output)).To(Equal(expectedHash))
				})

				It("Should run the interactive shell in login mode and read .profile", func() {
					clientArgs = getClientArgs(rsaPrivKeyPath)
					command := exec.Command(ssh3Path, clientArgs...)
					stdin, err := command.StdinPipe()
					Expect(err).ToNot(HaveOccurred())
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Consistently(session).ShouldNot(Exit())
					Eventually(session.Out, commandTimeout).Should(Say("hello from .profile"))
					_, err = stdin.Write([]byte("exit\n")) // 0x04 = EOT character, closing the bash session
					Expect(err).ToNot(HaveOccurred())
					Eventually(session, commandTimeout).Should(Exit(0))
				})

				Context("File transfer", func() {
					transferSpec := func(remoteFileName string) string {
						// explicit port and url path: user@host:port/url_path:remote_path
						return fmt.Sprintf("%s@%s%s:%s", username, serverBind, DEFAULT_URL_PATH, remoteFileName)
					}
					// getClientArgs cannot be reused here: it appends its own
					// host operand, and the transfer client takes exactly the
					// -transfer operands (see transferClientArgs)

					It("Should upload and download a file with matching checksums", func() {
						const payloadSize = 8 * 1024 * 1024
						payload := make([]byte, payloadSize)
						_, err := rand.Read(payload)
						Expect(err).ToNot(HaveOccurred())
						expectedHash := sha256.Sum256(payload)

						workspace, err := os.MkdirTemp("", "ssh3-fx-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						localUpload := path.Join(workspace, "upload.bin")
						Expect(os.WriteFile(localUpload, payload, 0o644)).To(Succeed())

						uploadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, localUpload, transferSpec("fx-upload.bin"))...)
						uploadOutput, err := uploadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "upload failed: %s", uploadOutput)

						localDownload := path.Join(workspace, "download.bin")
						downloadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, transferSpec("fx-upload.bin"), localDownload)...)
						downloadOutput, err := downloadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "download failed: %s", downloadOutput)

						downloaded, err := os.ReadFile(localDownload)
						Expect(err).ToNot(HaveOccurred())
						Expect(downloaded).To(HaveLen(payloadSize))
						Expect(sha256.Sum256(downloaded)).To(Equal(expectedHash))

						Expect(exec.Command(ssh3Path, append(getClientArgs(rsaPrivKeyPath), "rm", "fx-upload.bin")...).Run()).To(Succeed())
					})

					It("Should transfer a directory tree recursively with matching checksums", func() {
						workspace, err := os.MkdirTemp("", "ssh3-fx-tree-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						tree := path.Join(workspace, "tree")
						for _, dir := range []string{"", "sub", "sub/deep", "empty"} {
							Expect(os.MkdirAll(path.Join(tree, dir), 0o755)).To(Succeed())
						}
						manifest := map[string][]byte{}
						for _, file := range []struct {
							relative string
							size     int
						}{
							{relative: "top.bin", size: 1024},
							{relative: "sub/mid.bin", size: 65536},
							{relative: "sub/deep/deep.bin", size: 300},
						} {
							data := make([]byte, file.size)
							_, err := rand.Read(data)
							Expect(err).ToNot(HaveOccurred())
							Expect(os.WriteFile(path.Join(tree, filepath.FromSlash(file.relative)), data, 0o644)).To(Succeed())
							manifest[file.relative] = data
						}

						uploadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "-r", tree, transferSpec("fx-tree"))...)
						uploadOutput, err := uploadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "recursive upload failed: %s", uploadOutput)

						localMirror := path.Join(workspace, "mirror")
						downloadCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "-r", transferSpec("fx-tree"), localMirror)...)
						downloadOutput, err := downloadCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "recursive download failed: %s", downloadOutput)

						for relative, data := range manifest {
							mirrored, err := os.ReadFile(path.Join(localMirror, filepath.FromSlash(relative)))
							Expect(err).ToNot(HaveOccurred(), "missing %s in mirror", relative)
							Expect(mirrored).To(Equal(data), "content mismatch for %s", relative)
						}
						_, err = os.Stat(path.Join(localMirror, "empty"))
						Expect(err).ToNot(HaveOccurred(), "empty directory was not transferred")
					})

					It("Should resume an interrupted upload with --continue", func() {
						const payloadSize = 8 * 1024 * 1024
						payload := make([]byte, payloadSize)
						_, err := rand.Read(payload)
						Expect(err).ToNot(HaveOccurred())
						expectedHash := sha256.Sum256(payload)

						workspace, err := os.MkdirTemp("", "ssh3-fx-resume-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						fullFile := path.Join(workspace, "full.bin")
						Expect(os.WriteFile(fullFile, payload, 0o644)).To(Succeed())
						partialFile := path.Join(workspace, "partial.bin")
						Expect(os.WriteFile(partialFile, payload[:payloadSize/2], 0o644)).To(Succeed())

						// simulate an interrupted transfer: the first half is remote
						partialCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, partialFile, transferSpec("fx-continue.bin"))...)
						_, err = partialCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred())

						resumeCommand := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "--continue", fullFile, transferSpec("fx-continue.bin"))...)
						resumeOutput, err := resumeCommand.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "resume failed: %s", resumeOutput)

						backFile := path.Join(workspace, "back.bin")
						_, err = exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, transferSpec("fx-continue.bin"), backFile)...).CombinedOutput()
						Expect(err).ToNot(HaveOccurred())
						downloadedFile, err := os.ReadFile(backFile)
						Expect(err).ToNot(HaveOccurred())
						Expect(downloadedFile).To(HaveLen(payloadSize))
						Expect(sha256.Sum256(downloadedFile)).To(Equal(expectedHash))
					})

					It("Should pass checksum verification on upload", func() {
						workspace, err := os.MkdirTemp("", "ssh3-fx-sum-*")
						Expect(err).ToNot(HaveOccurred())
						defer os.RemoveAll(workspace)

						checksummed := path.Join(workspace, "checksummed.bin")
						data := make([]byte, 1024*1024)
						_, err = rand.Read(data)
						Expect(err).ToNot(HaveOccurred())
						Expect(os.WriteFile(checksummed, data, 0o644)).To(Succeed())

						command := exec.Command(ssh3Path, transferClientArgs(rsaPrivKeyPath, "--checksum", checksummed, transferSpec("fx-checksummed.bin"))...)
						output, err := command.CombinedOutput()
						Expect(err).ToNot(HaveOccurred(), "checksummed upload failed: %s", output)
					})
				})

				// It checks that upon executing the client with the -forward-tcp,
				// a TCP socket is indeed well open on the client and is indeed forwarded
				// through the SSH3 connection towards the specified remote IP and port.
				Context("TCP port forwarding", func() {
					testTCPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.TCPAddr, messageFromClient string, messageFromServer string) {
						// the bare loopback address of the remote family: the
						// local listener address is built with net.JoinHostPort
						localIP := "::1"
						if remoteAddr.IP.To4() != nil {
							localIP = "127.0.0.1"
						}
						serverStarted := make(chan struct{})
						// Start a TCP server on the specified remote IP and port
						go func() {
							defer close(serverStarted)
							defer GinkgoRecover()
							listener, err := net.ListenTCP("tcp", remoteAddr)
							Expect(err).ToNot(HaveOccurred())
							defer listener.Close()

							serverStarted <- struct{}{}

							conn, err := listener.Accept()
							Expect(err).ToNot(HaveOccurred())
							defer conn.Close()

							// Read message from client
							buffer := make([]byte, len(messageFromClient))
							_, err = conn.Read(buffer)
							Expect(err).ToNot(HaveOccurred())
							Expect(string(buffer)).To(Equal(messageFromClient))

							// Send message to client
							_, err = conn.Write([]byte(messageFromServer))
							Expect(err).ToNot(HaveOccurred())
							conn.(*net.TCPConn).CloseWrite()

							// Read from the client after receiving the message, assert EOF
							n, err := conn.Read(buffer)
							Expect(err).To(Equal(io.EOF))
							Expect(n).To(Equal(0))
						}()

						Eventually(serverStarted).Should(Receive())
						// Execute the client with TCP port forwarding

						additionalArgs := []string{}
						if proxyJump {
							additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
						}
						// -N: the forwarding client holds the connection open
						// without a session. Without it the client opens a shell
						// whose stdin is the empty one of the suite: the session
						// ends at once and the client exits, taking the local
						// listener with it before the probe can connect.
						additionalArgs = append(additionalArgs, "-N")
						additionalArgs = append(additionalArgs, "-forward-tcp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
						clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()

						// Try to connect to the local forwarded port
						localAddr := net.JoinHostPort(localIP, strconv.Itoa(int(localPort)))
						var conn net.Conn
						// connection refused might happen between the time when the process starts and actually listens the socket
						Eventually(func() error {
							var err error
							conn, err = net.Dial("tcp", localAddr)
							return err
						}, forwardReadyTimeout).ShouldNot(HaveOccurred())
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						// Send message from client
						n, err := conn.Write([]byte(messageFromClient))
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromClient)))

						// Close the client-side connection
						conn.(*net.TCPConn).CloseWrite()

						// Read message from server
						buffer := make([]byte, len(messageFromServer))
						conn.SetReadDeadline(time.Now().Add(1 * time.Second))
						n, err = conn.Read(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(string(buffer[:n])).To(Equal(messageFromServer))

						// If the messages are correctly exchanged, the forwarding is working as expected
						// Now, check that the TCP conn is well closed and that no additional byte was sent
						n, err = conn.Read(buffer)
						Expect(n).To(Equal(0))
						Expect(err).To(Equal(io.EOF))
					}

					It("works with small messages", func() {
						testTCPPortForwarding(8080, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
					})

					It("works through proxy jump", func() {
						testTCPPortForwarding(8084, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9092}, "hello from client", "hello from server")
					})

					It("works with messages larger than a typical MTU", func() {
						rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
						messageFromClient := make([]byte, 20000)
						messageFromServer := make([]byte, 20000)
						n, err := rng.Read(messageFromClient)
						Expect(n).To(Equal(len(messageFromClient)))
						Expect(err).ToNot(HaveOccurred())
						n, err = rng.Read(messageFromServer)
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(err).ToNot(HaveOccurred())
						testTCPPortForwarding(8081, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9093}, string(messageFromClient), string(messageFromServer))
					})

					It("works with IPv6 addresses", func() {
						// we first have to check whether IPv6 are enabled on that host, it is still often
						// not the case in many Docker containers...
						addrs, err := net.InterfaceAddrs()
						Expect(err).ToNot(HaveOccurred())
						if !IPv6LoopbackAvailable(addrs) {
							Skip("IPv6 not available on this host")
						}
						testTCPPortForwarding(8082, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
					})
				})
			})

			// It checks that upon executing the client with the -forward-udp,
			// a UDP socket is indeed well open on the client and is indeed forwarded
			// through the SSH3 connection towards the specified remote IP and port.
			Context("UDP port forwarding", func() {
				testUDPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.UDPAddr, messageFromClient, messageFromServer string) {
					// the bare loopback address of the remote family: the
					// local listener address is built with net.JoinHostPort
					localIP := "::1"
					if remoteAddr.IP.To4() != nil {
						localIP = "127.0.0.1"
					}

					serverStarted := make(chan struct{})
					// Start a UDP server on the specified remote IP and port
					go func() {
						defer close(serverStarted)
						defer GinkgoRecover()
						conn, err := net.ListenUDP("udp", remoteAddr)
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						serverStarted <- struct{}{}

						buffer := make([]byte, 2*len(messageFromClient))
						n, clientAddr, err := conn.ReadFromUDP(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(clientAddr.IP.String()).To(Equal(localIP))
						Expect(string(buffer[:n])).To(Equal(messageFromClient))

						// Send message to client
						_, err = conn.WriteToUDP([]byte(messageFromServer), clientAddr)
						Expect(err).ToNot(HaveOccurred())
					}()

					Eventually(serverStarted).Should(Receive())
					// Execute the client with UDP port forwarding

					additionalArgs := []string{}
					if proxyJump {
						additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
					}
					// -N: the forwarding client holds the connection open
					// without a session (see the TCP forwarding helper)
					additionalArgs = append(additionalArgs, "-N")
					additionalArgs = append(additionalArgs, "-forward-udp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
					clientArgs := getClientArgs(rsaPrivKeyPath, additionalArgs...)
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer session.Terminate()

					// Wait for some time to ensure that the client has established the forwarding
					time.Sleep(2 * time.Second)

					// if the remote addr is IPv4 (resp. IPv6), ssh3 listens on the IPv4 (resp. IPv6) loopback
					// Try to connect to the local forwarded port
					localAddr := net.JoinHostPort(localIP, strconv.Itoa(int(localPort)))

					var conn net.Conn
					Eventually(func() error {
						var err error
						conn, err = net.Dial("udp", localAddr)
						return err
					}, forwardReadyTimeout).ShouldNot(HaveOccurred())
					defer conn.Close()

					// Send message from client
					n, err := conn.Write([]byte(messageFromClient))
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromClient)))

					// Read message from server
					buffer := make([]byte, 2*len(messageFromServer))
					conn.SetReadDeadline(time.Now().Add(1 * time.Second))
					n, err = conn.Read(buffer)
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(string(buffer[:n])).To(Equal(messageFromServer))
				}

				It("works with small messages", func() {
					testUDPPortForwarding(8080, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
				})

				It("works through proxy jump", func() {
					testUDPPortForwarding(8084, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9092}, "hello from client", "hello from server")
				})

				// Due to current quic-go limitations, the max datagram size is limited to 1200, whatever the real MTU is,
				// so right now we test for 1150 messages and nothing more
				It("works with messages of 1150 bytes", func() {
					rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
					messageFromClient := make([]byte, 1150)
					messageFromServer := make([]byte, 1150)
					n, err := rng.Read(messageFromClient)
					Expect(n).To(Equal(len(messageFromClient)))
					Expect(err).ToNot(HaveOccurred())
					n, err = rng.Read(messageFromServer)
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(err).ToNot(HaveOccurred())
					testUDPPortForwarding(8081, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9093}, string(messageFromClient), string(messageFromServer))
				})

				It("works with IPv6 addresses", func() {
					// Check whether IPv6 is available on the host
					addrs, err := net.InterfaceAddrs()
					Expect(err).ToNot(HaveOccurred())
					if !IPv6LoopbackAvailable(addrs) {
						Skip("IPv6 not available on this host")
					}
					testUDPPortForwarding(8082, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
				})

			})

			Context("Server behaviour", func() {
				It("Should not grand access to non-authorized identity", func() {
					clientArgs = append(getClientArgs(attackerPrivKeyPath), "echo", "Hello, World!")

					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					// the identity is not in the authorized identities: the
					// server refuses the session, the command must not run and
					// the client must fail instead of reporting a success
					Eventually(session, commandTimeout).Should(Exit())
					Eventually(session).ShouldNot(Exit(0))
					Expect(session.Out.Contents()).ToNot(ContainSubstring("Hello, World!"))
					// the transport-level refusal is what the client can
					// report: the session channel is canceled by the remote
					// before any output arrives (the auth verdict itself is
					// logged by the server)
					Expect(string(session.Wait().Err.Contents())).To(ContainSubstring("Could not get message"))
				})
			})
		})
	})
})
