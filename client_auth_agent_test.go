package ssh3

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// The RSA-SHA2 flag of the agent sign request (the C canon
// s3_ssh3_agent_client.c): the algo rides the head of the key blob — the
// ssh-rsa keys sign the sha-256 variant (the flag 2, ssh-agent
// SSH_AGENT_RSA_SHA2_256, never the sha-1 default), the rest take the
// default. A sha-1 signature of the agent would ride a JWT the server
// refuses (the rsa-sha2-256 hint of the auth chain names the expected alg).

// recordingAgent captures the flags of the sign request.
type recordingAgent struct {
	agent.ExtendedAgent
	gotFlags agent.SignatureFlags
	gotKey   ssh.PublicKey
}

func (a *recordingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.gotFlags = flags
	a.gotKey = key
	return &ssh.Signature{Format: key.Type(), Blob: []byte("agent-signature")}, nil
}

func TestAgentSigningMethodSignsRSAWithSha256Flag(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate the rsa key: %s", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("could not wire the public key: %s", err)
	}
	rec := &recordingAgent{}
	m := &agentSigningMethod{Agent: rec, Key: pub}

	sig, err := m.Sign("the-signing-string", pub)
	if err != nil {
		t.Fatalf("the sign returned an error: %s", err)
	}
	if rec.gotFlags != agent.SignatureFlagRsaSha256 {
		t.Errorf("the rsa sign request rode flags %d, want the RSA-SHA2_256 flag %d", rec.gotFlags, agent.SignatureFlagRsaSha256)
	}
	if rec.gotKey != pub {
		t.Errorf("the sign request rode the wrong key")
	}
	if string(sig) != "agent-signature" {
		t.Errorf("the sign returned %q, want the agent signature blob passthrough", sig)
	}
	if m.Alg() != "RS256" {
		t.Errorf("the rsa signing method named %q, want RS256", m.Alg())
	}
}

func TestAgentSigningMethodEd25519TakesTheDefault(t *testing.T) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the ed25519 key: %s", err)
	}
	pub, err := ssh.NewPublicKey(edPriv.Public())
	if err != nil {
		t.Fatalf("could not wire the public key: %s", err)
	}
	rec := &recordingAgent{}
	m := &agentSigningMethod{Agent: rec, Key: pub}

	if _, err := m.Sign("the-signing-string", pub); err != nil {
		t.Fatalf("the sign returned an error: %s", err)
	}
	// the C canon: the rest of the keys take the default — no RSA flag on
	// a non-rsa key
	if rec.gotFlags != 0 {
		t.Errorf("the ed25519 sign request rode flags %d, want the default 0", rec.gotFlags)
	}
	if m.Alg() != "EdDSA" {
		t.Errorf("the ed25519 signing method named %q, want EdDSA", m.Alg())
	}
}
