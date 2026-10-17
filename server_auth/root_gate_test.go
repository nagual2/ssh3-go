package server_auth

import "testing"

// The sshd PermitRootLogin prohibit-password analog: root never authenticates
// by password, every other account is unaffected.
func TestPasswordLoginRefusedRoot(t *testing.T) {
	if !PasswordLoginRefused("root") {
		t.Fatal("PasswordLoginRefused(\"root\") = false, want true")
	}
	for _, username := range []string{"admin", "Root", "root2", "sudo-root", ""} {
		if PasswordLoginRefused(username) {
			t.Fatalf("PasswordLoginRefused(%q) = true, want false", username)
		}
	}
}
