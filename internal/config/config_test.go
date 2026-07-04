// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// write puts content into a fresh temp directory as job.conf and returns
// the full path.
func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "job.conf")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const valid = `
# full-line comment
source: /var/spool/out     # trailing comment
dst:   deploy@remote.example.org:/var/spool/in
file-user:  ^(app|deploy)$
file-group:
key: /etc/keys/k_ed25519

port: 2222
known-hosts: /etc/kh
mystery: value
`

func TestLoadValid(t *testing.T) {
	job, warnings, err := Load(write(t, valid), "/default/kh")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if job.Source != "/var/spool/out" {
		t.Errorf("Source = %q (comment or whitespace not stripped?)", job.Source)
	}
	if job.Dest != "deploy@remote.example.org" {
		t.Errorf("Dest = %q", job.Dest)
	}
	if job.SSHUser != "deploy" || job.Host != "remote.example.org" || job.RemoteDir != "/var/spool/in" {
		t.Errorf("split dst = (%q, %q, %q)", job.SSHUser, job.Host, job.RemoteDir)
	}
	if job.Port != 2222 {
		t.Errorf("Port = %d, want 2222", job.Port)
	}
	if job.KnownHosts != "/etc/kh" {
		t.Errorf("KnownHosts = %q, want the per-job override", job.KnownHosts)
	}
	if job.UserRe == nil || !job.UserRe.MatchString("app") || job.UserRe.MatchString("apple") {
		t.Errorf("UserRe does not behave as an anchored ^(app|deploy)$")
	}
	if job.GroupRe != nil {
		t.Errorf("empty file-group must mean no constraint (nil), got %v", job.GroupRe)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "mystery") {
		t.Errorf("warnings = %v, want exactly one about 'mystery'", warnings)
	}
}

func TestKnownHostsDefault(t *testing.T) {
	job, _, err := Load(write(t, "source: /s\ndst: h:/d\nkey: /k\n"), "/default/kh")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if job.KnownHosts != "/default/kh" {
		t.Errorf("KnownHosts = %q, want the default", job.KnownHosts)
	}
	if job.SSHUser != "root" {
		t.Errorf("SSHUser = %q, want root when dst has no user", job.SSHUser)
	}
	if job.Port != 22 {
		t.Errorf("Port = %d, want 22 by default", job.Port)
	}
}

func TestDstForms(t *testing.T) {
	cases := []struct {
		dst, dest, user, host, dir string
	}{
		{"host.example:/in", "host.example", "root", "host.example", "/in"},
		{"alice@host.example:/in", "alice@host.example", "alice", "host.example", "/in"},
		{"alice@[2001:db8::1]:/in", "alice@[2001:db8::1]", "alice", "2001:db8::1", "/in"},
		{"[::1]:/in", "[::1]", "root", "::1", "/in"},
	}
	for _, c := range cases {
		dest, user, host, dir, err := splitDst(c.dst)
		if err != nil {
			t.Errorf("splitDst(%q): %v", c.dst, err)
			continue
		}
		if dest != c.dest || user != c.user || host != c.host || dir != c.dir {
			t.Errorf("splitDst(%q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				c.dst, dest, user, host, dir, c.dest, c.user, c.host, c.dir)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name, conf, want string
	}{
		{"missing source", "dst: h:/d\nkey: /k\n", "source"},
		{"missing dst", "source: /s\nkey: /k\n", "dst"},
		{"missing key", "source: /s\ndst: h:/d\n", "key"},
		{"relative source", "source: s\ndst: h:/d\nkey: /k\n", "absolute"},
		{"relative remote dir", "source: /s\ndst: h:d\nkey: /k\n", "absolute"},
		{"bare ipv6", "source: /s\ndst: 2001:db8::1:/d\nkey: /k\n", "absolute"},
		{"no colon in dst", "source: /s\ndst: host\nkey: /k\n", "missing"},
		{"empty user", "source: /s\ndst: @h:/d\nkey: /k\n", "empty user"},
		{"empty host", "source: /s\ndst: :/d\nkey: /k\n", "empty host"},
		{"port out of range", "source: /s\ndst: h:/d\nkey: /k\nport: 70000\n", "port"},
		{"port not a number", "source: /s\ndst: h:/d\nkey: /k\nport: ssh\n", "port"},
		{"bad pattern", "source: /s\ndst: h:/d\nkey: /k\nfile-user: (\n", "file-user"},
		{"relative known-hosts", "source: /s\ndst: h:/d\nkey: /k\nknown-hosts: kh\n", "known-hosts"},
	}
	for _, c := range cases {
		_, _, err := Load(write(t, c.conf), "/kh")
		if err == nil {
			t.Errorf("%s: Load succeeded, want error", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestMalformedLineWarns(t *testing.T) {
	_, warnings, err := Load(write(t, "source: /s\ndst: h:/d\nkey: /k\njust some words\n"), "/kh")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "line 4") {
		t.Errorf("warnings = %v, want one naming line 4", warnings)
	}
}
