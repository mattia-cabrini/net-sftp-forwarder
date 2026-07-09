// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

package hostkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
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
	cb, err := Callback(kh, Strict)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	err = cb(testHost, testAddr, genKey(t))
	if err == nil {
		t.Fatal("unknown host must fail closed under Strict")
	}
	if !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("error %q should tell the admin how to seed the host", err)
	}
}

func TestStrictRejectsMissingFile(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "does_not_exist")
	if _, err := Callback(kh, Strict); err == nil {
		t.Fatal("missing known_hosts must be an error under Strict")
	}
	if _, err := os.Stat(kh); !os.IsNotExist(err) {
		t.Error("Strict must not create the file")
	}
}

func TestAcceptNewPinsThenVerifies(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts") // deliberately missing
	cb, err := Callback(kh, AcceptNew)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	key := genKey(t)
	if err := cb(testHost, testAddr, key); err != nil {
		t.Fatalf("first contact under AcceptNew must pin, got %v", err)
	}

	// A fresh Strict callback over the same file must now trust that key...
	strict, err := Callback(kh, Strict)
	if err != nil {
		t.Fatalf("Callback over pinned file: %v", err)
	}
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
	cb, err := Callback(kh, AcceptNew)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	newKey := genKey(t)
	if err := cb(testHost, testAddr, newKey); err != nil {
		t.Fatalf("pinning after a newline-less entry: %v", err)
	}

	// Both the pre-existing pin and the fresh one must verify afterwards.
	strict, err := Callback(kh, Strict)
	if err != nil {
		t.Fatalf("Callback over appended file: %v", err)
	}
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
	cb, err := Callback(kh, AcceptNew)
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	presented := genKey(t)
	err = cb(testHost, testAddr, presented)
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
