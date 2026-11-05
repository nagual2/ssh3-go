//go:build linux && !disable_password_auth

// the SSHole hardening pins (the OpenSSH 10.6p2 alignment): the
// non-password shadow records refuse before any crypt call, the crypt
// NULL of the musl unsupported schemes rides the error (never the
// empty string), the over-boundary passwords refuse, the compare runs
// in constant time.
package unix_util

import (
	"strings"
	"testing"
)

func TestHashUsable(t *testing.T) {
	unusable := []string{"", "*", "!", "!!", "!$6$deadbeef", "x"}
	for _, h := range unusable {
		if hashUsable(h) {
			t.Errorf("hashUsable(%q) = true, want false", h)
		}
	}
	usable := []string{"$6$salt$hashhash", "$y$salt$hashhash", "abC123def456"}
	for _, h := range usable {
		if !hashUsable(h) {
			t.Errorf("hashUsable(%q) = false, want true", h)
		}
	}
}

func TestCryptRefusesUnusableSetting(t *testing.T) {
	for _, setting := range []string{"", "*", "!", "x"} {
		if _, err := Crypt("anypassword", setting); err == nil {
			t.Errorf("Crypt with the setting %q must refuse", setting)
		}
	}
}

func TestCryptRefusesOverBoundaryPassword(t *testing.T) {
	// the SHA-512 hash of "s3testpw" with the salt "s3saltsalt"
	setting := "$6$s3saltsalt$YbF/Cru.RUspxTy4VkyMybmBXEtQQd112pzJIU7QBJBmYRFE4vI1/RZwJvjHx5jrohCsYy2.MI7t6oK/NFC5h1"

	if _, err := Crypt("s3testpw", setting); err != nil {
		t.Fatalf("the honest credential must ride: %s", err)
	}

	long := strings.Repeat("a", 257)
	if _, err := Crypt(long, setting); err == nil {
		t.Error("the password above the 256-byte boundary must refuse")
	}
}

func TestComparePasswordWithHashedPassword(t *testing.T) {
	setting := "$6$s3saltsalt$YbF/Cru.RUspxTy4VkyMybmBXEtQQd112pzJIU7QBJBmYRFE4vI1/RZwJvjHx5jrohCsYy2.MI7t6oK/NFC5h1"

	ok, err := ComparePasswordWithHashedPassword("s3testpw", setting)
	if err != nil || !ok {
		t.Errorf("the right password must ride (ok=%v err=%s)", ok, err)
	}

	ok, err = ComparePasswordWithHashedPassword("wrongpw", setting)
	if err != nil || ok {
		t.Errorf("the wrong password must refuse (ok=%v err=%s)", ok, err)
	}

	// the passwordless account: the empty shadow field refuses (the
	// SSHole shape) — the empty candidate never authenticates
	ok, err = ComparePasswordWithHashedPassword("", "")
	if err == nil || ok {
		t.Errorf("the empty stored hash must refuse (ok=%v err=%s)", ok, err)
	}
	ok, err = ComparePasswordWithHashedPassword("anything", "")
	if err == nil || ok {
		t.Errorf("the empty stored hash must refuse any candidate (ok=%v err=%s)", ok, err)
	}
}
