// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

// Package hostkey implements host-key verification against a known_hosts
// file, with the two policies the forwarder supports: strict (fail closed on
// unknown hosts; the default) and accept-new (pin an unknown host's key on
// first contact). A key that conflicts with a pinned one fails under every
// policy — that is either a re-keyed host or a man-in-the-middle, and no
// policy of this tool may silently accept it.
package hostkey

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Policy selects how unknown hosts are treated.
type Policy int

const (
	// Strict rejects hosts that have no entry in known_hosts. This is the
	// default: an unseeded host fails closed.
	Strict Policy = iota
	// AcceptNew records an unknown host's key on first contact and trusts
	// it from then on, like OpenSSH's StrictHostKeyChecking=accept-new.
	AcceptNew
)

// ParsePolicy maps the NET_SFTP_FORWARDER_STRICT spellings to a Policy:
// "yes" is Strict, "accept-new" is AcceptNew. Anything else reports
// ok == false and yields Strict — an unknown spelling must fail closed.
func ParsePolicy(s string) (policy Policy, ok bool) {
	switch s {
	case "yes":
		return Strict, true
	case "accept-new":
		return AcceptNew, true
	}
	return Strict, false
}

// Callback builds an ssh.HostKeyCallback that verifies hosts against the
// known_hosts file at path under the given policy. The file format is
// OpenSSH's own (hashed entries included), so files seeded by ssh-keyscan
// or recorded by the OpenSSH client are read without translation.
func Callback(path string, policy Policy) (ssh.HostKeyCallback, error) {
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("known_hosts %s: %w", path, err)
		}
		if policy != AcceptNew {
			return nil, fmt.Errorf("known_hosts %s does not exist; create it and seed it with ssh-keyscan", path)
		}
		// accept-new may start from nothing: create the file (0600 — it is
		// trust data) so the parser below has something to read.
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, fmt.Errorf("creating known_hosts %s: %w", path, err)
		}
	}

	verify, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("parsing known_hosts %s: %w", path, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err // revoked key, unparsable file, ...: always fatal
		}
		if len(keyErr.Want) > 0 {
			// The host presented a key that conflicts with what is pinned.
			// Never accept this, under any policy. It is a re-keyed host, a
			// man-in-the-middle — or a host whose other key types were never
			// pinned and the negotiation picked one of those; seeding with
			// plain `ssh-keyscan host` (all key types) avoids that case.
			return fmt.Errorf("host key for %s conflicts with the one pinned in %s: %w", hostname, path, err)
		}
		if policy == AcceptNew {
			return record(path, hostname, key)
		}
		return fmt.Errorf("unknown host %s: no entry in %s (seed it: %s >> %s)",
			hostname, path, keyscanHint(hostname), path)
	}, nil
}

// record appends hostname's key to the known_hosts file so that every later
// run verifies against it. The forwarder's run lock guarantees a single
// writer, so no file locking is needed here.
func record(path, hostname string, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("recording host key for %s: %w", hostname, err)
	}
	defer f.Close()
	line := knownhosts.Line([]string{hostname}, key) + "\n"
	// A hand-seeded file may lack its final newline; appending straight
	// onto it would merge the new entry into the last line and corrupt
	// both pins.
	if info, err := f.Stat(); err != nil {
		return fmt.Errorf("recording host key for %s: %w", hostname, err)
	} else if info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, info.Size()-1); err != nil {
			return fmt.Errorf("recording host key for %s: %w", hostname, err)
		}
		if last[0] != '\n' {
			line = "\n" + line
		}
	}
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("recording host key for %s: %w", hostname, err)
	}
	return nil
}

// keyscanHint renders the ssh-keyscan invocation that would seed an entry
// for hostname, which arrives from the ssh client as "host:port".
func keyscanHint(hostname string) string {
	host, port, err := net.SplitHostPort(hostname)
	if err != nil {
		return "ssh-keyscan " + hostname
	}
	if port != "22" {
		return fmt.Sprintf("ssh-keyscan -p %s %s", port, host)
	}
	return "ssh-keyscan " + host
}
