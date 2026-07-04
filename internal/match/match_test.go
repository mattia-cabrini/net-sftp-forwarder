// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

package match

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestCompileEmptyMeansNoConstraint(t *testing.T) {
	re, err := Compile("")
	if err != nil || re != nil {
		t.Fatalf("Compile(\"\") = (%v, %v), want (nil, nil)", re, err)
	}
	if !Matches(re, "anything at all") {
		t.Error("nil pattern must match everything")
	}
}

func TestCompileAnchors(t *testing.T) {
	re, err := Compile("log")
	if err != nil {
		t.Fatal(err)
	}
	if !Matches(re, "log") {
		t.Error("'log' must match itself")
	}
	// The brief's own example: an unanchored pattern must not substring-match.
	if Matches(re, "catalog") || Matches(re, "logs") {
		t.Error("'log' must not match 'catalog' or 'logs'")
	}
}

func TestCompileAlternation(t *testing.T) {
	for _, pattern := range []string{"app|deploy", "^(app|deploy)$"} {
		re, err := Compile(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if !Matches(re, "app") || !Matches(re, "deploy") {
			t.Errorf("%q must match both alternatives", pattern)
		}
		if Matches(re, "apps") || Matches(re, "redeploy") {
			t.Errorf("%q must stay anchored around the whole alternation", pattern)
		}
	}
}

func TestCompileBadPattern(t *testing.T) {
	if _, err := Compile("("); err == nil {
		t.Error("Compile(\"(\") must fail")
	}
}

func TestOwnerOfOwnFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	owner, group, err := Owner(info)
	if err != nil {
		t.Fatalf("Owner: %v", err)
	}
	me, err := user.Current()
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	if owner != me.Username {
		t.Errorf("owner = %q, want %q", owner, me.Username)
	}
	if group == "" {
		t.Error("group must never be empty (decimal gid at worst)")
	}
}
