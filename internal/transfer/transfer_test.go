// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

package transfer

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
)

// localSession runs an in-process SFTP server over a pipe, so Forward is
// exercised against a real protocol implementation — including
// posix-rename@openssh.com — without a network or an sshd.
func localSession(t *testing.T) *Session {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	server, err := sftp.NewServer(serverEnd)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve()
	client, err := sftp.NewClientPipe(clientEnd, clientEnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return &Session{client: client}
}

func TestForwardAppearsAtomicallyUnderFinalName(t *testing.T) {
	s := localSession(t)
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// A name with spaces: the native transport must handle it (brief §6).
	name := "hello world.txt"
	local := filepath.Join(srcDir, name)
	if err := os.WriteFile(local, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Leftovers from an "interrupted" earlier attempt must both be replaced:
	// the stale .part by Create's truncation, the old final by PosixRename.
	if err := os.WriteFile(filepath.Join(dstDir, "."+name+".part"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, name), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.Forward(local, dstDir); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dstDir, name))
	if err != nil {
		t.Fatalf("final file: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("final content = %q, want %q", got, "payload")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "."+name+".part")); !os.IsNotExist(err) {
		t.Error(".part temporary left behind after a successful rename")
	}
	// Forward must not remove the local file — that is the caller's move,
	// made only after Forward reports success.
	if _, err := os.Stat(local); err != nil {
		t.Errorf("local file touched by Forward: %v", err)
	}
}

func TestForwardFailsIntoMissingRemoteDir(t *testing.T) {
	s := localSession(t)
	local := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(local, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Forward(local, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("uploading into a missing remote directory must fail")
	}
}

func TestLoadKeyRefusesOpenPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte("irrelevant"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(p); err == nil {
		t.Fatal("a group/world-readable key must be refused")
	}
}
