#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mattia Cabrini
#
# Syntax-check every shell script in the repository. The Go-side checks
# (gofmt, vet, test, build) run from the Makefile 'check' target, which
# calls this script first.

set -eu

for script in install/*.sh; do
	sh -n "$script"
	echo "ok: sh -n $script"
done
