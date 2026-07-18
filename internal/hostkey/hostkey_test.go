// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

package hostkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func genKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func genECDSAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// mkCallback builds a Checker and returns its policy callback, failing the
// test if the file cannot be opened.
func mkCallback(t *testing.T, path string, policy Policy) ssh.HostKeyCallback {
	t.Helper()
	c, err := New(path, policy)
	if err != nil {
		t.Fatalf("New(%s): %v", path, err)
	}
	return c.Callback()
}

// testAddr stands in for the peer address; the verifier prefers the dialed
// hostname, so the value barely matters.
var testAddr = &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}

const testHost = "remote.example:22"

func TestParsePolicy(t *testing.T) {
	cases := []struct {
		in   string
		want Policy
		ok   bool
	}{
		{"yes", Strict, true},
		{"accept-new", AcceptNew, true},
		{"no", Strict, false}, // unknown spellings fail closed
		{"", Strict, false},
	}
	for _, c := range cases {
		got, ok := ParsePolicy(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParsePolicy(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestStrictRejectsUnknownHost(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := mkCallback(t, kh, Strict)(testHost, testAddr, genKey(t))
	if err == nil {
		t.Fatal("unknown host must fail closed under Strict")
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("error %q should tell the admin how to seed the host", err)
	}
}

func TestStrictRejectsMissingFile(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "does_not_exist")
	if _, err := New(kh, Strict); err == nil {
		t.Fatal("missing known_hosts must be an error under Strict")
	}
	if _, err := os.Stat(kh); !os.IsNotExist(err) {
		t.Error("Strict must not create the file")
	}
}

func TestAcceptNewPinsThenVerifies(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts") // deliberately missing
	key := genKey(t)
	if err := mkCallback(t, kh, AcceptNew)(testHost, testAddr, key); err != nil {
		t.Fatalf("first contact under AcceptNew must pin, got %v", err)
	}

	// A fresh Strict callback over the same file must now trust that key...
	strict := mkCallback(t, kh, Strict)
	if err := strict(testHost, testAddr, key); err != nil {
		t.Fatalf("pinned key did not verify: %v", err)
	}
	// ...and reject any other.
	if err := strict(testHost, testAddr, genKey(t)); err == nil {
		t.Fatal("a conflicting key must fail under Strict")
	}
}

func TestAcceptNewAppendsAfterMissingFinalNewline(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	oldKey := genKey(t)
	// A hand-seeded entry (printf, some editors) may lack its final
	// newline; pinning a second host must not merge into it.
	pinned := knownhosts.Line([]string{"pinned.example:22"}, oldKey)
	if err := os.WriteFile(kh, []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	newKey := genKey(t)
	if err := mkCallback(t, kh, AcceptNew)(testHost, testAddr, newKey); err != nil {
		t.Fatalf("pinning after a newline-less entry: %v", err)
	}

	// Both the pre-existing pin and the fresh one must verify afterwards.
	strict := mkCallback(t, kh, Strict)
	if err := strict("pinned.example:22", testAddr, oldKey); err != nil {
		t.Errorf("pre-existing pin corrupted by the append: %v", err)
	}
	if err := strict(testHost, testAddr, newKey); err != nil {
		t.Errorf("appended pin does not verify: %v", err)
	}
}

func TestConflictFailsEvenUnderAcceptNew(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	pinnedKey := genKey(t)
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{testHost}, pinnedKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	presented := genKey(t)
	err := mkCallback(t, kh, AcceptNew)(testHost, testAddr, presented)
	if err == nil {
		t.Fatal("a conflicting key must fail even under AcceptNew")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error %q should report a host key mismatch", err)
	}
	// The message must name both what arrived and what was pinned, by
	// fingerprint, so the cause is diagnosable straight from the log.
	if !strings.Contains(err.Error(), ssh.FingerprintSHA256(presented)) {
		t.Errorf("error %q should include the presented key's fingerprint", err)
	}
	if !strings.Contains(err.Error(), ssh.FingerprintSHA256(pinnedKey)) {
		t.Errorf("error %q should include the pinned key's fingerprint", err)
	}
}

// TestAlgorithmsAdvertiseOnlyPinnedTypes is the regression test for the
// negotiation footgun: a host pinned with only ed25519 must make the client
// advertise only ed25519, so the server cannot answer with (say) its ECDSA
// key and be reported as a spurious mismatch.
func TestAlgorithmsAdvertiseOnlyPinnedTypes(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{testHost}, genKey(t))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(kh, Strict)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := c.Algorithms(testHost)
	if len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Fatalf("Algorithms = %v, want exactly [%s]", got, ssh.KeyAlgoED25519)
	}
}

func TestAlgorithmsCoverAllPinnedTypesAndSkipUnknown(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	lines := knownhosts.Line([]string{testHost}, genKey(t)) + "\n" +
		knownhosts.Line([]string{testHost}, genECDSAKey(t)) + "\n"
	if err := os.WriteFile(kh, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(kh, Strict)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := c.Algorithms(testHost)
	if !slices.Contains(got, ssh.KeyAlgoED25519) || !slices.Contains(got, ssh.KeyAlgoECDSA256) {
		t.Errorf("Algorithms = %v, want both ed25519 and ecdsa-nistp256", got)
	}
	// A host with no entry constrains nothing: nil lets the client use its
	// default set, which accept-new needs to learn a first key.
	if got := c.Algorithms("unseen.example:22"); got != nil {
		t.Errorf("unknown host: Algorithms = %v, want nil", got)
	}
}
