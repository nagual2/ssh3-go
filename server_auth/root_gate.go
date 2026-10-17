package server_auth

// The root-account password gate: the PermitRootLogin prohibit-password
// analog of the sshd canon (maintainer decision 2026-10-17, CTO_TASK §7c item 13).
// The root account authenticates by key only; a password attempt is refused
// before the password backend is consulted, like sshd refusing root password
// logins regardless of the account's shadow state.

// PasswordLoginRefused reports whether password authentication must be
// refused for the account regardless of the password check result.
func PasswordLoginRefused(username string) bool {
	return username == "root"
}
