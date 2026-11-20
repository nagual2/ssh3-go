package ticketkey

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// a random nginx 80-byte body: 16 name + 32 hmac + 32 aes
func randomBody(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("could not generate the random body: %s", err)
	}
	return buf
}

func TestParseNginx80TakesTheAesPart(t *testing.T) {
	body := randomBody(t, NginxKeyLen)
	key, err := Parse(body)
	if err != nil {
		t.Fatalf("the 80-byte body refused: %s", err)
	}
	if string(key[:]) != string(body[48:80]) {
		t.Fatalf("the key seed is not the aes part (the last 32 bytes)")
	}
}

func TestParseLegacy48TakesAesHmac(t *testing.T) {
	// the legacy nginx form: 16 name + 16 aes + 16 hmac — the Go seed rides
	// aes||hmac (the bytes after the name)
	body := randomBody(t, LegacyKeyLen)
	key, err := Parse(body)
	if err != nil {
		t.Fatalf("the 48-byte legacy body refused: %s", err)
	}
	if string(key[:]) != string(body[16:48]) {
		t.Fatalf("the key seed is not the legacy aes||hmac pair")
	}
}

func TestParseRefusesTheBrokenShapes(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 47, 49, 63, 64, 79, 81, 96, 160} {
		_, err := Parse(randomBody(t, n))
		if err == nil {
			t.Fatalf("the %d-byte body passed", n)
		}
		if !errors.Is(err, errNotNginx) {
			t.Fatalf("the %d-byte body failed with the wrong error kind: %s", n, err)
		}
	}
}

func TestDefaultPathRidesThePrivKeyDirectory(t *testing.T) {
	got := DefaultPath("/etc/ssh3/priv.key")
	if want := filepath.Join("/etc/ssh3", DefaultFileName); got != want {
		t.Fatalf("DefaultPath(/etc/ssh3/priv.key) = %q, want %q", got, want)
	}
	// the windows separators ride the same derivation on the windows host
	if runtime.GOOS == "windows" {
		got := DefaultPath(`C:\keys\priv.key`)
		if want := filepath.Join(`C:\keys`, DefaultFileName); got != want {
			t.Fatalf("DefaultPath(C:\\keys\\priv.key) = %q, want %q", got, want)
		}
	}
	// the bare private key name rides the current directory (the canon: the
	// key file belongs to the same store as the privkey, no slash = the cwd)
	if got := DefaultPath("priv.key"); got != DefaultFileName {
		t.Fatalf("DefaultPath(priv.key) = %q, want the bare %q", got, DefaultFileName)
	}
}

func TestLoadGeneratesTheMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)

	key, modTime, err := Load(path)
	if err != nil {
		t.Fatalf("Load on the missing file failed: %s", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the generated file does not exist: %s", err)
	}
	if len(body) != NginxKeyLen {
		t.Fatalf("the generated file is %d bytes, want %d", len(body), NginxKeyLen)
	}
	if string(key[:]) != string(body[48:80]) {
		t.Fatalf("the returned key is not the generated body's aes part")
	}
	if modTime.IsZero() {
		t.Fatalf("the mtime baseline did not ride back")
	}

	// the owner-only mode of the fresh file (the windows host keeps a loose
	// view of the unix modes, the assertion is the linux one)
	if runtime.GOOS == "linux" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("could not stat the generated file: %s", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("the generated file rides the %v mode, want 0600", info.Mode().Perm())
		}
	}
}

func TestLoadSurvivesTheRestartWithoutRegeneration(t *testing.T) {
	// the restart semantics: the second Load of the same file yields the
	// same key and leaves the file bytes untouched
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)

	key1, _, err := Load(path)
	if err != nil {
		t.Fatalf("the first Load failed: %s", err)
	}
	body1, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read the first body: %s", err)
	}

	key2, _, err := Load(path)
	if err != nil {
		t.Fatalf("the second Load failed: %s", err)
	}
	body2, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read the second body: %s", err)
	}
	if key1 != key2 {
		t.Fatalf("the restart regenerated the key")
	}
	if string(body1) != string(body2) {
		t.Fatalf("the restart rewrote the file bytes")
	}
}

func TestLoadRegeneratesTheBrokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	if err := os.WriteFile(path, randomBody(t, 20), 0644); err != nil {
		t.Fatalf("could not write the broken body: %s", err)
	}

	key, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load on the broken file failed: %s", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read the regenerated file: %s", err)
	}
	if len(body) != NginxKeyLen {
		t.Fatalf("the regenerated file is %d bytes, want %d", len(body), NginxKeyLen)
	}
	if string(key[:]) != string(body[48:80]) {
		t.Fatalf("the key is not the regenerated body's aes part")
	}
}

func TestLoadRefusesTheUnwritablePath(t *testing.T) {
	// the canon: a failed path keeps the daemon alive on the in-memory keys
	// — Load reports the failure instead of arming
	path := filepath.Join(t.TempDir(), "no-such-dir", DefaultFileName)
	if _, _, err := Load(path); err == nil {
		t.Fatalf("Load on the unwritable path passed")
	}
}

func TestLoadRefusesTheUnreadableFile(t *testing.T) {
	// a read failure is not a regeneration: the error rides back
	if runtime.GOOS != "linux" {
		t.Skip("the unix permission model drives the shape")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	if err := os.WriteFile(path, randomBody(t, NginxKeyLen), 0000); err != nil {
		t.Fatalf("could not write the body: %s", err)
	}
	if _, _, err := Load(path); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Load on the unreadable file failed with the wrong kind: %s", err)
	}
}

// the unit tests arm a bare config (the keys and the rotation channel are
// the tested surface); the certificate-bearing serving shapes ride the
// restart_test.go proofs
func newTLSConfigForTest(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func TestArmArmsTheConfigAndRidesTheRotationChannel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	if len(m.keys) != 1 {
		t.Fatalf("the armed history holds %d keys, want 1", len(m.keys))
	}
	// the GetConfigForClient callback is the rotation channel: the serving
	// config is the single http3 clone, the per-handshake config carries the
	// armed keys of the moment
	if cfg.GetConfigForClient == nil {
		t.Fatalf("the rotation channel did not ride")
	}
	forClient, err := cfg.GetConfigForClient(nil)
	if err != nil {
		t.Fatalf("the rotation channel failed: %s", err)
	}
	if forClient != cfg {
		t.Fatalf("the rotation channel returned a foreign config")
	}
}

func TestArmFailsOnTheUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", DefaultFileName)
	cfg := newTLSConfigForTest(t)
	m := NewManager(cfg, path)
	if err := m.Arm(); err == nil {
		t.Fatalf("Arm on the unwritable path passed")
	}
	if cfg.GetConfigForClient != nil {
		t.Fatalf("the failed arm rode the rotation channel anyway")
	}
}

func TestPollRotatesTheChangedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	oldKey := m.keys[0]

	// the operator rotates: a fresh valid body with a moved mtime
	newBody := randomBody(t, NginxKeyLen)
	if err := os.WriteFile(path, newBody, 0600); err != nil {
		t.Fatalf("could not write the rotated body: %s", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("could not move the mtime: %s", err)
	}

	m.Poll()

	if len(m.keys) != 2 {
		t.Fatalf("the armed history holds %d keys, want 2", len(m.keys))
	}
	if string(m.keys[0][:]) != string(newBody[48:80]) {
		t.Fatalf("the fresh key does not ride first")
	}
	if m.keys[1] != oldKey {
		t.Fatalf("the old key dropped from the decrypt-only tail")
	}
}

func TestPollKeepsTheKeysOnTheBrokenRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	armed := append([][32]byte(nil), m.keys...)

	// the operator breaks the file mid-rotation
	broken := randomBody(t, 20)
	if err := os.WriteFile(path, broken, 0600); err != nil {
		t.Fatalf("could not write the broken body: %s", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("could not move the mtime: %s", err)
	}

	m.Poll()

	if len(m.keys) != len(armed) || m.keys[0] != armed[0] {
		t.Fatalf("the broken rotation replaced the armed keys")
	}
	// the file stays untouched: the operator's write is not destroyed
	body, err := os.ReadFile(path)
	if err != nil || string(body) != string(broken) {
		t.Fatalf("the broken rotation rewrote the operator's file")
	}
}

func TestPollKeepsTheKeysOnTheMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	armed := append([][32]byte(nil), m.keys...)
	if err := os.Remove(path); err != nil {
		t.Fatalf("could not remove the key file: %s", err)
	}

	m.Poll()

	if len(m.keys) != len(armed) || m.keys[0] != armed[0] {
		t.Fatalf("the missing file dropped the armed keys")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the missing-file rotation recreated the file")
	}
}

func TestPollIsANoOpOnTheUnchangedMtime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	armed := append([][32]byte(nil), m.keys...)
	// the content changes but the mtime stays (the touch-less overwrite the
	// watcher must not adopt ahead of the mtime contract)
	if err := os.WriteFile(path, randomBody(t, NginxKeyLen), 0600); err != nil {
		t.Fatalf("could not rewrite the body: %s", err)
	}
	if err := os.Chtimes(path, m.modTime, m.modTime); err != nil {
		t.Fatalf("could not restore the mtime: %s", err)
	}

	m.Poll()

	if len(m.keys) != len(armed) || m.keys[0] != armed[0] {
		t.Fatalf("the unchanged mtime rotated the keys")
	}
}

func TestPollDedupesTheSameKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	armed := append([][32]byte(nil), m.keys...)

	// the same bytes ride back (the mtime moved, the key did not)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read the body: %s", err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("could not rewrite the body: %s", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("could not move the mtime: %s", err)
	}

	m.Poll()

	if len(m.keys) != 1 || m.keys[0] != armed[0] {
		t.Fatalf("the same key duplicated the armed history")
	}
}

func TestRotateBoundsTheHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	for i := 0; i < maxArmedKeys+3; i++ {
		if !m.rotate([32]byte{byte(i)}) {
			t.Fatalf("the rotation %d did not adopt the fresh key", i)
		}
	}
	if len(m.keys) != maxArmedKeys {
		t.Fatalf("the armed history grew to %d keys, want the %d bound", len(m.keys), maxArmedKeys)
	}
}

func TestRotateMovesTheKnownKeyToFront(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultFileName)
	cfg := newTLSConfigForTest(t)

	m := NewManager(cfg, path)
	if err := m.Arm(); err != nil {
		t.Fatalf("Arm failed: %s", err)
	}
	k1 := m.keys[0]
	if !m.rotate([32]byte{2}) {
		t.Fatalf("the rotation did not adopt the fresh key")
	}
	if !m.rotate(k1) {
		t.Fatalf("the known key did not ride back")
	}
	if m.keys[0] != k1 || len(m.keys) != 2 {
		t.Fatalf("the known key did not move to the front without duplicating: %d keys", len(m.keys))
	}
}
