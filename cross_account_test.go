package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// mockConnMetadata implements gossh.ConnMetadata for testing.
type mockConnMetadata struct {
	user          string
	sessionID     []byte
	clientVersion []byte
	serverVersion []byte
}

func (m mockConnMetadata) User() string          { return m.user }
func (m mockConnMetadata) SessionID() []byte     { return m.sessionID }
func (m mockConnMetadata) ClientVersion() []byte { return m.clientVersion }
func (m mockConnMetadata) ServerVersion() []byte { return m.serverVersion }
func (m mockConnMetadata) RemoteAddr() net.Addr  { return nil }
func (m mockConnMetadata) LocalAddr() net.Addr   { return nil }

// TestApplyConnMetadataRefreshesUser verifies that applyConnMetadata updates
// the username on every call, even after the session ID has already been set.
// This is a regression test for the cross-account authentication bypass where
// a stale username from a failed attempt persisted to subsequent attempts.
func TestApplyConnMetadataRefreshesUser(t *testing.T) {
	t.Parallel()

	ctx, cancel := newContext(nil)
	defer cancel()

	sessionID := []byte("test-session-id")

	// First call: alice authenticates (and fails).
	alice := mockConnMetadata{
		user:          "alice",
		sessionID:     sessionID,
		clientVersion: []byte("SSH-2.0-test"),
		serverVersion: []byte("SSH-2.0-server"),
	}
	applyConnMetadata(ctx, alice)

	if got := ctx.User(); got != "alice" {
		t.Fatalf("after first call: User() = %q, want %q", got, "alice")
	}
	if ctx.Value(ContextKeySessionID) == nil {
		t.Fatal("session ID should be set after first call")
	}

	// Second call: bob authenticates on the same connection.
	bob := mockConnMetadata{
		user:          "bob",
		sessionID:     sessionID,
		clientVersion: []byte("SSH-2.0-test"),
		serverVersion: []byte("SSH-2.0-server"),
	}
	applyConnMetadata(ctx, bob)

	if got := ctx.User(); got != "bob" {
		t.Fatalf("after second call: User() = %q, want %q; stale username from first attempt persisted", got, "bob")
	}
}

// TestApplyConnMetadataConnectionScopedValues verifies that truly
// connection-scoped values (session ID, versions, addresses) are set once
// and not overwritten on subsequent calls.
func TestApplyConnMetadataConnectionScopedValues(t *testing.T) {
	t.Parallel()

	ctx, cancel := newContext(nil)
	defer cancel()

	first := mockConnMetadata{
		user:          "alice",
		sessionID:     []byte("session-1"),
		clientVersion: []byte("SSH-2.0-client-v1"),
		serverVersion: []byte("SSH-2.0-server-v1"),
	}
	applyConnMetadata(ctx, first)

	sessionID := ctx.SessionID()
	clientVersion := ctx.ClientVersion()
	serverVersion := ctx.ServerVersion()

	// Second call with different connection-scoped values.
	second := mockConnMetadata{
		user:          "bob",
		sessionID:     []byte("session-2"),
		clientVersion: []byte("SSH-2.0-client-v2"),
		serverVersion: []byte("SSH-2.0-server-v2"),
	}
	applyConnMetadata(ctx, second)

	// Username must update.
	if got := ctx.User(); got != "bob" {
		t.Fatalf("User() = %q, want %q", got, "bob")
	}

	// Connection-scoped values must not change.
	if got := ctx.SessionID(); got != sessionID {
		t.Fatalf("SessionID() changed: got %q, want %q", got, sessionID)
	}
	if got := ctx.ClientVersion(); got != clientVersion {
		t.Fatalf("ClientVersion() changed: got %q, want %q", got, clientVersion)
	}
	if got := ctx.ServerVersion(); got != serverVersion {
		t.Fatalf("ServerVersion() changed: got %q, want %q", got, serverVersion)
	}
}

// TestCrossAccountPublicKeyAttack simulates the reported attack at the
// callback level: a failed public-key attempt as alice, followed by a
// successful attempt as bob signed with alice's key. The PublicKeyHandler
// must see "bob" on the second attempt, not the stale "alice".
func TestCrossAccountPublicKeyAttack(t *testing.T) {
	t.Parallel()

	_, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceSigner, err := gossh.NewSignerFromKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	alicePub := aliceSigner.PublicKey()

	accounts := map[string]gossh.PublicKey{
		"alice": alicePub,
	}

	srv := &Server{
		PublicKeyHandler: func(ctx Context, key PublicKey) bool {
			known, ok := accounts[ctx.User()]
			return ok && KeysEqual(known, key)
		},
	}
	if err := srv.ensureHostSigner(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := newContext(srv)
	defer cancel()
	config := srv.config(ctx)

	sessionID := []byte("test-session-id")

	// Attempt 1: alice offers her own key. Handler sees alice, accepts.
	aliceConn := mockConnMetadata{user: "alice", sessionID: sessionID}
	_, err = config.PublicKeyCallback(aliceConn, alicePub)
	if err != nil {
		t.Fatalf("alice's own key should be accepted: %v", err)
	}

	// Simulate a failed auth so the connection continues.
	// (In the real protocol the server rejects and the client retries.)

	// Attempt 2: attacker requests bob, signs with alice's key.
	bobConn := mockConnMetadata{user: "bob", sessionID: sessionID}
	_, err = config.PublicKeyCallback(bobConn, alicePub)
	if err == nil {
		t.Fatal("alice's key must NOT authenticate bob; cross-account attack succeeded")
	}

	// The handler must have seen "bob", not the stale "alice".
	if got := ctx.User(); got != "bob" {
		t.Fatalf("after bob attempt: ctx.User() = %q, want %q", got, "bob")
	}
}

// TestCrossAccountPasswordThenPublicKeyAttack simulates the password-priming
// variant: a failed password attempt as alice, then a public-key attempt as
// bob signed with alice's key.
func TestCrossAccountPasswordThenPublicKeyAttack(t *testing.T) {
	t.Parallel()

	_, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceSigner, err := gossh.NewSignerFromKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	alicePub := aliceSigner.PublicKey()

	accounts := map[string]gossh.PublicKey{
		"alice": alicePub,
	}

	srv := &Server{
		PasswordHandler: func(ctx Context, password string) bool {
			return false // always reject
		},
		PublicKeyHandler: func(ctx Context, key PublicKey) bool {
			known, ok := accounts[ctx.User()]
			return ok && KeysEqual(known, key)
		},
	}
	if err := srv.ensureHostSigner(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := newContext(srv)
	defer cancel()
	config := srv.config(ctx)

	sessionID := []byte("test-session-id")

	// Attempt 1: alice fails password auth.
	aliceConn := mockConnMetadata{user: "alice", sessionID: sessionID}
	_, err = config.PasswordCallback(aliceConn, []byte("wrong-password"))
	if err == nil {
		t.Fatal("alice's password should have been rejected")
	}

	// Attempt 2: attacker requests bob, signs with alice's key.
	bobConn := mockConnMetadata{user: "bob", sessionID: sessionID}
	_, err = config.PublicKeyCallback(bobConn, alicePub)
	if err == nil {
		t.Fatal("alice's key must NOT authenticate bob after failed alice password; cross-account attack succeeded")
	}
	if got := ctx.User(); got != "bob" {
		t.Fatalf("after bob attempt: ctx.User() = %q, want %q", got, "bob")
	}
}

// TestLegitimateAuthAfterFailedAttempt verifies that bob's own key still
// works after alice's failed attempt on the same connection.
func TestLegitimateAuthAfterFailedAttempt(t *testing.T) {
	t.Parallel()

	_, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aliceSigner, err := gossh.NewSignerFromKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	_, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bobSigner, err := gossh.NewSignerFromKey(bobPriv)
	if err != nil {
		t.Fatal(err)
	}

	accounts := map[string]gossh.PublicKey{
		"alice": aliceSigner.PublicKey(),
		"bob":   bobSigner.PublicKey(),
	}

	srv := &Server{
		PublicKeyHandler: func(ctx Context, key PublicKey) bool {
			known, ok := accounts[ctx.User()]
			return ok && KeysEqual(known, key)
		},
	}
	if err := srv.ensureHostSigner(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := newContext(srv)
	defer cancel()
	config := srv.config(ctx)

	sessionID := []byte("test-session-id")

	// Alice fails with a throwaway key.
	_, throwawayPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	throwawaySigner, err := gossh.NewSignerFromKey(throwawayPriv)
	if err != nil {
		t.Fatal(err)
	}
	aliceConn := mockConnMetadata{user: "alice", sessionID: sessionID}
	_, err = config.PublicKeyCallback(aliceConn, throwawaySigner.PublicKey())
	if err == nil {
		t.Fatal("throwaway key should be rejected for alice")
	}

	// Bob authenticates with his own key. Must succeed.
	bobConn := mockConnMetadata{user: "bob", sessionID: sessionID}
	_, err = config.PublicKeyCallback(bobConn, bobSigner.PublicKey())
	if err != nil {
		t.Fatalf("bob's own key must be accepted after alice's failure: %v", err)
	}
	if got := ctx.User(); got != "bob" {
		t.Fatalf("ctx.User() = %q, want %q", got, "bob")
	}
}
