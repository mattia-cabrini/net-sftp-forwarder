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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"

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

// Checker verifies presented host keys against a known_hosts file under a
// policy, and reports which key algorithms that file pins for a host. The
// client is told to advertise only those algorithms, so the negotiation
// cannot settle on a key type the file has no entry for — the footgun where a
// host pinned with only ed25519 is handed the server's ECDSA key and
// spuriously reported as a mismatch. The file format is OpenSSH's own (hashed
// entries included), so files seeded by ssh-keyscan or recorded by the
// OpenSSH client are read without translation.
type Checker struct {
	verify ssh.HostKeyCallback // raw knownhosts verifier
	path   string
	policy Policy
}

// New opens the known_hosts file at path and prepares a Checker under the
// given policy. Under Strict a missing file is a fatal error; under AcceptNew
// a missing file is created empty (0600 — it is trust data).
func New(path string, policy Policy) (*Checker, error) {
	if _, err := os.Stat(path); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("known_hosts %s: %w", path, err)
		}
		if policy != AcceptNew {
			return nil, fmt.Errorf("known_hosts %s does not exist; create it and seed it with ssh-keyscan", path)
		}
		// accept-new may start from nothing: create the file so the parser
		// below has something to read.
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			return nil, fmt.Errorf("creating known_hosts %s: %w", path, err)
		}
	}

	verify, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("parsing known_hosts %s: %w", path, err)
	}
	return &Checker{verify: verify, path: path, policy: policy}, nil
}

// Callback returns the ssh.HostKeyCallback that enforces the policy.
func (c *Checker) Callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := c.verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err // revoked key, unparsable file, ...: always fatal
		}
		if len(keyErr.Want) > 0 {
			// The host presented a key that matches none of the pinned ones.
			// Never accept this, under any policy. The got/pinned pair below
			// makes the cause diagnosable from the log: a re-keyed host or a
			// man-in-the-middle changes the fingerprint of a pinned type.
			// (The old "unpinned type was negotiated" cause is now prevented
			// by Algorithms, so a mismatch here signals a genuinely wrong key.)
			return fmt.Errorf("host key mismatch for %s in %s: got %s, pinned %s",
				hostname, c.path, describeKey(key), describeKnownKeys(keyErr.Want))
		}
		if c.policy == AcceptNew {
			return record(c.path, hostname, key)
		}
		return fmt.Errorf("unknown host %s: no entry in %s (seed it: %s >> %s)",
			hostname, c.path, keyscanHint(hostname), c.path)
	}
}

// Algorithms returns the host-key algorithms pinned for addr ("host:port"),
// so the client advertises only types this file can verify. It returns nil
// for an unknown host, leaving the client's default set in place — which
// accept-new needs in order to learn (and then pin) the host's key.
//
// The pins are read straight from the knownhosts verifier: probing it with a
// throwaway key yields a KeyError whose Want lists every key recorded for the
// host, so this reuses the package's own matching (hashed entries included)
// rather than re-parsing the file.
func (c *Checker) Algorithms(addr string) []string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var keyErr *knownhosts.KeyError
	if err := c.verify(addr, stringAddr(addr), probe); !errors.As(err, &keyErr) || len(keyErr.Want) == 0 {
		return nil // unknown host, or no usable pins: do not constrain
	}
	return algorithmsFor(keyErr.Want)
}

// algorithmsFor maps the pinned keys to the host-key algorithm names to
// advertise, de-duplicated. A pinned RSA key is offered with its SHA-2
// signature variants first (legacy ssh-rsa last), so a server that has
// retired SHA-1 still negotiates against the same key.
func algorithmsFor(want []knownhosts.KnownKey) []string {
	seen := map[string]bool{}
	var algos []string
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, k := range want {
		switch k.Key.Type() {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA256)
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSA)
		default:
			add(k.Key.Type())
		}
	}
	return algos
}

// stringAddr is a net.Addr whose String() is a fixed "host:port", used only
// to probe the knownhosts verifier, which reads remote.String().
type stringAddr string

func (stringAddr) Network() string  { return "tcp" }
func (a stringAddr) String() string { return string(a) }

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

// describeKey renders a public key as "<type> <sha256-fingerprint>", the
// same fingerprint form ssh-keygen -l and OpenSSH's own logs print, so a
// mismatch line can be compared against them without extra tooling.
func describeKey(key ssh.PublicKey) string {
	return key.Type() + " " + ssh.FingerprintSHA256(key)
}

// describeKnownKeys renders the pinned keys that a presented key failed to
// match, so a mismatch line states plainly what was expected next to what
// arrived. A differing type points at an unseeded key; a differing
// fingerprint of the same type points at a re-keyed host or a forgery.
func describeKnownKeys(want []knownhosts.KnownKey) string {
	if len(want) == 0 {
		return "(none)"
	}
	parts := make([]string, len(want))
	for i, k := range want {
		parts[i] = describeKey(k.Key)
	}
	return strings.Join(parts, ", ")
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
