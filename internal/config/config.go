// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

// Package config reads net-sftp-forwarder service-configuration files: plain
// line-based "key: value" files, one per transfer job (see
// service.conf.sample for the format). Parsing and validation happen together
// in Load; a Job that comes back non-nil is ready to run without further
// checks.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"net-sftp-forwarder/internal/match"
)

// Job is one validated transfer job.
type Job struct {
	Source     string         // absolute local directory whose files are forwarded
	Dest       string         // "[user@]host" exactly as written in dst:, for log lines
	SSHUser    string         // user to authenticate as; "root" when dst: omits it
	Host       string         // bare host name or address (brackets stripped from IPv6)
	Port       int            // SSH port; 22 unless port: overrides it
	RemoteDir  string         // absolute directory on the remote host
	KeyPath    string         // absolute path of the SSH private key
	KnownHosts string         // known_hosts file used for host-key verification
	UserRe     *regexp.Regexp // owner-user gate; nil = no constraint
	GroupRe    *regexp.Regexp // owner-group gate; nil = no constraint
}

// recognised is the complete set of configuration keys. Anything else is
// reported as a warning and ignored, so a typo cannot silently disable a
// gate or a key path.
var recognised = map[string]bool{
	"source":      true,
	"dst":         true,
	"file-user":   true,
	"file-group":  true,
	"key":         true,
	"known-hosts": true,
	"port":        true,
}

// Load parses and validates the service configuration at path.
// defaultKnownHosts applies when the file carries no known-hosts: override.
// Warnings (unknown keys, malformed lines) are returned even when loading
// succeeds; a non-nil error means the whole job must be skipped.
func Load(path, defaultKnownHosts string) (*Job, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	vals := make(map[string]string)
	var warnings []string
	for n, line := range strings.Split(string(data), "\n") {
		// A '#' starts a comment to end of line, wherever it appears;
		// the documented consequence is that values can never contain '#'.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			warnings = append(warnings, fmt.Sprintf("line %d is not a 'key: value' line", n+1))
			continue
		}
		key = strings.TrimSpace(key)
		if !recognised[key] {
			warnings = append(warnings, fmt.Sprintf("unknown key '%s'", key))
			continue
		}
		vals[key] = strings.TrimSpace(value)
	}

	job, err := validate(vals, defaultKnownHosts)
	if err != nil {
		return nil, warnings, err
	}
	return job, warnings, nil
}

// validate turns the raw key/value map into a Job, enforcing the rules of
// the format: required keys present, paths absolute, port in range,
// patterns compilable, dst well formed.
func validate(vals map[string]string, defaultKnownHosts string) (*Job, error) {
	job := &Job{Port: 22, KnownHosts: defaultKnownHosts}

	for _, req := range []string{"source", "dst", "key"} {
		if vals[req] == "" {
			return nil, fmt.Errorf("missing required key '%s'", req)
		}
	}
	job.Source = vals["source"]
	if !filepath.IsAbs(job.Source) {
		return nil, fmt.Errorf("'source' must be an absolute path, got '%s'", job.Source)
	}
	job.KeyPath = vals["key"]
	if !filepath.IsAbs(job.KeyPath) {
		return nil, fmt.Errorf("'key' must be an absolute path, got '%s'", job.KeyPath)
	}
	if kh := vals["known-hosts"]; kh != "" {
		if !filepath.IsAbs(kh) {
			return nil, fmt.Errorf("'known-hosts' must be an absolute path, got '%s'", kh)
		}
		job.KnownHosts = kh
	}
	if p := vals["port"]; p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("'port' must be an integer between 1 and 65535, got '%s'", p)
		}
		job.Port = n
	}

	var err error
	if job.UserRe, err = match.Compile(vals["file-user"]); err != nil {
		return nil, fmt.Errorf("'file-user': %v", err)
	}
	if job.GroupRe, err = match.Compile(vals["file-group"]); err != nil {
		return nil, fmt.Errorf("'file-group': %v", err)
	}

	job.Dest, job.SSHUser, job.Host, job.RemoteDir, err = splitDst(vals["dst"])
	if err != nil {
		return nil, fmt.Errorf("'dst': %v", err)
	}
	return job, nil
}

// splitDst separates "[user@]host:/absolute/dir" into the destination text
// (everything before the path, kept verbatim for log lines), the SSH user,
// the bare host, and the remote directory.
//
// The first colon after the host splits destination from path, so IPv6
// literals must be written in brackets ("user@[2001:db8::1]:/dir") — a bare
// one would make the split ambiguous. When no user is given, root is
// assumed: cron runs the forwarder as root and there is no ssh_config to
// supply a per-host default.
//
// install/config.sh's connection test re-implements this split in shell;
// keep the two in sync.
func splitDst(dst string) (destText, user, host, dir string, err error) {
	user = "root"
	rest := dst
	// A user part is only recognised when the '@' comes before any ':' or
	// '[', so an '@' inside the remote path cannot be mistaken for one.
	if i := strings.IndexAny(rest, "@[:"); i >= 0 && rest[i] == '@' {
		user = rest[:i]
		rest = rest[i+1:]
		if user == "" {
			return "", "", "", "", fmt.Errorf("empty user before '@' in '%s'", dst)
		}
	}

	var path string
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", "", "", "", fmt.Errorf("unterminated '[' in '%s'", dst)
		}
		host = rest[1:end]
		if end+1 >= len(rest) || rest[end+1] != ':' {
			return "", "", "", "", fmt.Errorf("expected ':' after ']' in '%s'", dst)
		}
		path = rest[end+2:]
	} else {
		var ok bool
		host, path, ok = strings.Cut(rest, ":")
		if !ok {
			return "", "", "", "", fmt.Errorf("missing ':/remote/dir' in '%s'", dst)
		}
	}
	if host == "" {
		return "", "", "", "", fmt.Errorf("empty host in '%s'", dst)
	}
	if !strings.HasPrefix(path, "/") {
		return "", "", "", "", fmt.Errorf("remote directory must be absolute in '%s' (bracket IPv6 literals: user@[::1]:/dir)", dst)
	}
	destText = strings.TrimSuffix(dst, ":"+path)
	return destText, user, host, path, nil
}
