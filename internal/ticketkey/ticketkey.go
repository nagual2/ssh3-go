// Package ticketkey arms the server tls.Config with session ticket keys that
// ride a persistent file, so the tickets issued in one daemon lifetime keep
// decrypting after a restart — the warm 0-RTT reconnect survives the daemon
// (the ssh3-c wave-13 canon, commit 26f23eb; the Go fork rides the same
// shape, R14-4).
//
// The file rides the nginx 80-byte form: 16 ticket-name bytes + 32
// HMAC-SHA256 key bytes + 32 AES key bytes. The 48-byte nginx legacy form
// (16 name + 16 aes + 16 hmac, the aes-128/short-hmac shape) rides too. The
// canon of the missing and the broken body: the first lifetime of the key
// generates (the owner-only 0600 mode — the file is the plain-text of every
// ticket the daemon ever issued) and a broken body regenerates; a path that
// cannot be written keeps the daemon alive on its ephemeral in-memory keys
// (the pre-wave-13 shape) behind a warning. The startup semantics are the C
// ones; the rotation watcher is the Go-only increment (the C server loads
// its keys once at startup — the OpenSSL ticket callback holds one key —
// while the Go multi-key API of SetSessionTicketKeys admits the live
// rotation, so the mtime watcher adopts a rotated file at the 60 s default
// cadence, the fresh key sealing first and the armed keys staying in the
// decrypt-only tail for the in-flight tickets).
//
// The file is the shared thing, not the wire tickets. Go expands the 32-byte
// seed it takes from the file through its own KDF (crypto/tls
// ticketKeyFromBytes runs the seed through sha512) into its wire keys, while
// the C server seals its tickets with the OpenSSL callback over the raw
// name/hmac/aes bytes: one file arms both servers, each derives its own
// ticket material deterministically from the same bytes. The 80-byte form
// rides the AES part (the last 32 bytes) as the Go seed; the 48-byte legacy
// form rides the aes||hmac pair, which lands exactly on the Go internal
// split of a seed (the aes key is the first 16 bytes, the hmac key the last
// 16). A client always resumes against the server that issued the ticket —
// the ticket is an opaque blob of its issuer — so the cross-implementation
// wire-key interop is not needed: only the layout interop is the canon (one
// key file, both servers, no second secret store to rotate).
package ticketkey

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// NginxKeyLen is the nginx 80-byte key file form (16 name + 32 hmac +
	// 32 aes).
	NginxKeyLen = 80
	// LegacyKeyLen is the nginx 48-byte legacy form (16 name + 16 aes +
	// 16 hmac).
	LegacyKeyLen = 48
	// DefaultFileName lives beside the private key (the canon: the key file
	// belongs to the same secret store as the daemon's private key — the
	// /etc/ssh3 layout of the unit files).
	DefaultFileName = "session-ticket.key"
	// DefaultPollInterval is the key-file mtime poll of the rotation
	// watcher. The C canon has no rotation (the keys load once at startup);
	// the Go multi-key API admits the live rotation, the default cadence is
	// the 60 s poll.
	DefaultPollInterval = time.Minute
	// maxArmedKeys bounds the decrypt-only tail of the armed history: the
	// newest key seals the tickets, the tail keeps the in-flight tickets of
	// the past rotations decryptable.
	maxArmedKeys = 4
)

// errNotNginx marks a body that is neither the 80-byte form nor the 48-byte
// legacy one (the Parse error kind; the startup regeneration and the
// rotation skip both ride on it).
var errNotNginx = errors.New("the key file body is not the nginx form")

// DefaultPath derives the key file path beside the private key (the canon:
// the same directory as the -key argument; a bare private key file name
// rides the current directory).
func DefaultPath(privKeyPath string) string {
	return filepath.Join(filepath.Dir(privKeyPath), DefaultFileName)
}

// Parse validates a key file body in the nginx form and returns the Go
// session ticket key seed: the AES part (the last 32 bytes) of the 80-byte
// form, the aes||hmac pair of the 48-byte legacy one. Any other length is a
// broken body (the canon knows no structure check — the fresh file rides the
// random bytes, the length is the whole contract).
func Parse(buf []byte) ([32]byte, error) {
	var key [32]byte
	switch len(buf) {
	case NginxKeyLen:
		copy(key[:], buf[48:80])
	case LegacyKeyLen:
		copy(key[:], buf[16:48])
	default:
		return key, fmt.Errorf("%w: the body is %d bytes, want %d or %d",
			errNotNginx, len(buf), NginxKeyLen, LegacyKeyLen)
	}
	return key, nil
}

// Generate writes a fresh random key file (the nginx 80-byte form, the
// owner-only 0600 mode of the canon) and returns the fresh body.
func Generate(path string) ([]byte, error) {
	buf := make([]byte, NginxKeyLen)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("could not generate the random key bytes: %w", err)
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadFile reads a valid key file without touching it: the strict shape the
// rotation watcher rides on (a missing or broken body is an error there —
// the armed keys stay, the operator's write is not destroyed).
func ReadFile(path string) ([32]byte, time.Time, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, time.Time{}, err
	}
	key, err := Parse(buf)
	if err != nil {
		return [32]byte{}, time.Time{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return [32]byte{}, time.Time{}, err
	}
	return key, info.ModTime(), nil
}

// Load reads the key file with the startup semantics of the canon: a valid
// body yields its seed and mtime baseline; a missing body generates (the
// first lifetime of the key) and a broken one regenerates; a body that
// cannot be written (the path, the permissions) returns the error — the
// caller keeps the ephemeral in-process keys behind the warning. The
// modification time of the loaded file rides back: the watcher holds it as
// the rotation baseline.
func Load(path string) ([32]byte, time.Time, error) {
	key, modTime, err := ReadFile(path)
	if err == nil {
		return key, modTime, nil
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// the first lifetime of the key: generate and arm
	case errors.Is(err, errNotNginx):
		// the broken body rides the regeneration: the old tickets die, the
		// new lifetime starts clean (the canon)
		log.Warn().Msgf("session ticket key %s: %s, regenerating", path, err)
	default:
		// a read failure is not a regeneration (the permissions of the
		// secret store): the daemon keeps its in-memory keys
		return [32]byte{}, time.Time{}, err
	}
	buf, err := Generate(path)
	if err != nil {
		return [32]byte{}, time.Time{}, fmt.Errorf("could not write the generated key file: %w", err)
	}
	log.Info().Msgf("session ticket key %s generated", path)
	key, err = Parse(buf)
	if err != nil {
		return [32]byte{}, time.Time{}, err // unreachable: the fresh body is the 80-byte form
	}
	info, err := os.Stat(path)
	if err != nil {
		return [32]byte{}, time.Time{}, err
	}
	return key, info.ModTime(), nil
}

// Manager arms a serving tls.Config with the keys of the key file and runs
// the rotation watcher. The manager is not thread-safe: Arm rides once
// before the watcher starts, the polls ride on the watcher goroutine alone —
// the crossing into the concurrent handshakes is the thread-safe
// SetSessionTicketKeys of the config.
type Manager struct {
	cfg     *tls.Config
	path    string
	keys    [][32]byte // the armed history, newest first
	modTime time.Time  // the rotation baseline of the loaded file
}

// NewManager rides the config the daemon serves with (the one
// http3.ConfigureTLSConfig clones for the QUIC listener) and the key file
// path.
func NewManager(cfg *tls.Config, path string) *Manager {
	return &Manager{cfg: cfg, path: path}
}

// Setup resolves nothing by itself — it arms the config from the key file
// and returns the manager of the rotation watcher. A nil manager rides back
// when the key file could not be armed: the config keeps the ephemeral
// in-process keys (the pre-wave-13 shape — the client tickets die on the
// restart) and the daemon stays alive behind the warning (the canon).
func Setup(cfg *tls.Config, path string) *Manager {
	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		log.Warn().Msgf("the session ticket keys stay in the process memory "+
			"(the client tickets die on the restart): %s", err)
		return nil
	}
	return m
}

// Arm loads the key file and arms the config: the config keys become the
// file key and the GetConfigForClient callback rides the rotation channel.
//
// The channel exists because the serving QUIC listener clones the config
// once (http3.ConfigureTLSConfig at the quic.ListenAddrEarly call site —
// crypto/tls shares the armed keys between a config and its clones, but the
// later SetSessionTicketKeys replaces only the slice of the config it is
// called on). The callback hands the armed config to every handshake, so
// each handshake reads the keys of the moment through the fresh clone the
// http3 layer itself makes of the returned config; the initial keys were
// armed before the listener anyway, so the callback changes nothing about
// the first handshake and everything about the rotations.
func (m *Manager) Arm() error {
	key, modTime, err := Load(m.path)
	if err != nil {
		return err
	}
	m.keys = [][32]byte{key}
	m.modTime = modTime
	m.cfg.SetSessionTicketKeys(m.keys)
	m.cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return m.cfg, nil
	}
	log.Info().Msgf("session ticket key %s armed (the tickets survive the restart)", m.path)
	return nil
}

// Poll runs one rotation step: a changed file mtime re-arms the config with
// the fresh key first (the armed keys stay in the decrypt-only tail, the
// in-flight tickets keep resuming); a missing or broken file keeps the
// armed keys behind a warning and leaves the file untouched (the operator's
// write may still be in flight) — the baseline mtime stays, so the next
// poll retries. The same key re-read is a no-op (the touch without the
// rotation), the tail stays bounded.
func (m *Manager) Poll() {
	info, err := os.Stat(m.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Warn().Msgf("could not stat the session ticket key file %s: %s", m.path, err)
		}
		return
	}
	if info.ModTime().Equal(m.modTime) {
		return
	}
	key, modTime, err := ReadFile(m.path)
	if err != nil {
		log.Warn().Msgf("the session ticket key rotation skipped, keeping %d armed key(s): %s",
			len(m.keys), err)
		return
	}
	if m.rotate(key) {
		m.cfg.SetSessionTicketKeys(m.keys)
		log.Info().Msgf("session ticket key %s rotated, %d key(s) armed", m.path, len(m.keys))
	}
	m.modTime = modTime
}

// rotate prepends the fresh key: a key already armed moves to the front
// instead of duplicating (the operator rotated back), the tail drops past
// the bound. Returns whether the config needs the re-arm.
func (m *Manager) rotate(key [32]byte) bool {
	if len(m.keys) > 0 && m.keys[0] == key {
		return false
	}
	for i, k := range m.keys {
		if k == key {
			rest := append(m.keys[:i:i], m.keys[i+1:]...)
			m.keys = append([][32]byte{key}, rest...)
			return true
		}
	}
	m.keys = append([][32]byte{key}, m.keys...)
	if len(m.keys) > maxArmedKeys {
		m.keys = m.keys[:maxArmedKeys]
	}
	return true
}

// Run drives the rotation watcher: one mtime poll per interval, the stop
// rides the context cancellation (the shutdown context of the daemon).
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Poll()
			}
		}
	}()
}
