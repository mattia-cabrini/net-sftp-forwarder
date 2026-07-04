// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

// Package match implements the eligibility gate: resolving a file's owner
// user and group, and matching them against a job's patterns.
package match

import (
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"syscall"
)

// Compile turns a user-supplied pattern into an anchored, full-string
// matcher. An empty pattern means "no constraint" and yields nil — the
// opposite of what compiling the empty string would give.
func Compile(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	// \A...\z anchors the whole string regardless of any flags inside the
	// pattern; the non-capturing group keeps alternations intact, so "a|b"
	// means "exactly a or exactly b", not "starts with a or ends with b".
	return regexp.Compile(`\A(?:` + pattern + `)\z`)
}

// Matches reports whether value satisfies re. A nil re (empty pattern)
// matches everything.
func Matches(re *regexp.Regexp, value string) bool {
	return re == nil || re.MatchString(value)
}

// Owner resolves the owning user and group names of a file from its stat
// information. A uid or gid with no name on this system is reported as its
// decimal string, so patterns can match raw numeric ids too.
func Owner(info os.FileInfo) (userName, groupName string, err error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Cannot happen on the supported platforms (Linux and the BSDs);
		// guarded so a future port fails loudly instead of matching nothing.
		return "", "", fmt.Errorf("no unix ownership information for '%s'", info.Name())
	}
	return userByID(st.Uid), groupByID(st.Gid), nil
}

// userNames and groupNames memoize id→name lookups for the lifetime of the
// run: a spool full of files usually has one or two owners, and each lookup
// can cost a full /etc/passwd scan or an NSS round trip. The process is
// single-threaded and lives well under a minute, so plain maps suffice.
var (
	userNames  = map[uint32]string{}
	groupNames = map[uint32]string{}
)

func userByID(uid uint32) string {
	if name, ok := userNames[uid]; ok {
		return name
	}
	id := strconv.FormatUint(uint64(uid), 10)
	name := id
	if u, err := user.LookupId(id); err == nil {
		name = u.Username
	}
	userNames[uid] = name
	return name
}

func groupByID(gid uint32) string {
	if name, ok := groupNames[gid]; ok {
		return name
	}
	id := strconv.FormatUint(uint64(gid), 10)
	name := id
	if g, err := user.LookupGroupId(id); err == nil {
		name = g.Name
	}
	groupNames[gid] = name
	return name
}
