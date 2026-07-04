// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

// Package transfer moves files to a remote host over SFTP. One Session is
// one SSH connection with the SFTP subsystem opened on it; a job opens a
// single Session and forwards all of its eligible files through it.
//
// SFTP is deliberate: it works against restricted remote accounts —
// including a nologin shell with ForceCommand internal-sftp — because it
// never asks the remote to run a shell command, and it needs nothing on the
// far side beyond a stock sshd.
package transfer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// dialTimeout bounds TCP connect plus SSH handshake. Without it a
// black-holed remote would hold the run lock far longer than the
// once-a-minute cadence expects.
const dialTimeout = 30 * time.Second

// LoadKey reads and parses a job's private key. It first refuses keys that
// are group- or world-accessible, mirroring OpenSSH's own check. Keys are
// used unattended from cron, so passphrase-protected keys are unsupported.
func LoadKey(keyPath string) (ssh.Signer, error) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", keyPath, err)
	}
	if m := info.Mode().Perm(); m&0o077 != 0 {
		return nil, fmt.Errorf("key %s: mode %04o is group/world-accessible; chmod 0600 it", keyPath, m)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("key %s is passphrase-protected; unattended use needs an unencrypted key", keyPath)
		}
		return nil, fmt.Errorf("key %s: %w", keyPath, err)
	}
	return signer, nil
}

// Session is one job's SSH connection with the SFTP subsystem opened on it.
type Session struct {
	conn   *ssh.Client // nil in tests that drive the SFTP client directly
	client *sftp.Client
}

// Dial opens the SSH connection and the SFTP subsystem for a job.
func Dial(user, host string, port int, signer ssh.Signer, hostKey ssh.HostKeyCallback) (*Session, error) {
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKey,
		Timeout:         dialTimeout,
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return nil, err
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("opening sftp subsystem: %w", err)
	}
	return &Session{conn: conn, client: client}, nil
}

// Forward uploads the local file into remoteDir under its own basename.
// The upload goes to a temporary ".<name>.part" first — the leading dot
// keeps it out of '*' globs, the suffix out of extension globs — and is then
// renamed into place, so a consumer on the remote side never sees a partial
// file. Forward does not remove the local file; that is the caller's move,
// made only after Forward reports success.
func (s *Session) Forward(localPath, remoteDir string) error {
	name := filepath.Base(localPath)
	tmp := path.Join(remoteDir, "."+name+".part")
	final := path.Join(remoteDir, name)

	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening local file: %w", err)
	}
	defer src.Close()

	// Create truncates a leftover .part from an interrupted earlier attempt,
	// which is exactly the recovery we want — never clean those up.
	dst, err := s.client.Create(tmp)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmp, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return fmt.Errorf("uploading to %s: %w", tmp, err)
	}
	// SFTP writes are pipelined; Close carries the upload's final status.
	// Ignoring it would report torn uploads as successes.
	if err := dst.Close(); err != nil {
		return fmt.Errorf("uploading to %s: %w", tmp, err)
	}

	// posix-rename@openssh.com atomically replaces an existing target,
	// unlike the plain SFTP rename, which fails if the target exists.
	// Every OpenSSH sshd supports it.
	if err := s.client.PosixRename(tmp, final); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmp, final, err)
	}
	return nil
}

// Close tears down the SFTP subsystem and the SSH connection.
func (s *Session) Close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
}
