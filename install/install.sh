#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mattia Cabrini
#
# Idempotent installer for net-sftp-forwarder (run via `sudo make install`,
# which builds the binary first). Installs the binary, creates the
# configuration tree, and writes the marked cron line into /etc/crontab.
# Safe to re-run: everything is updated in place, and an admin's live
# *.conf files and known_hosts are never touched.

set -eu

LIBEXEC=/usr/local/libexec/net-sftp-forwarder
ETCDIR=/usr/local/etc/net-sftp-forwarder
CRONTAB=/etc/crontab
MARKER='# net-sftp-forwarder' # must match uninstall.sh
BINARY=build/net-sftp-forwarder-run

if [ "$(id -u)" -ne 0 ]; then
	echo 'install.sh: must be run as root (try: sudo make install)' >&2
	exit 1
fi
if [ ! -f "$BINARY" ]; then
	echo "install.sh: $BINARY not found; run 'make' first" >&2
	exit 1
fi

install -d -m 0755 "$LIBEXEC"
install -m 0755 "$BINARY" "$LIBEXEC/net-sftp-forwarder-run"

install -d -m 0750 "$ETCDIR"
install -d -m 0750 "$ETCDIR/conf.d"

# Ship the sample once; never overwrite anything an admin may have edited.
if [ ! -f "$ETCDIR/conf.d/service.conf.sample" ]; then
	install -m 0640 service.conf.sample "$ETCDIR/conf.d/service.conf.sample"
fi

# An empty known_hosts makes the strict default fail closed until the admin
# seeds it (see README, "Host keys").
if [ ! -f "$ETCDIR/known_hosts" ]; then
	: >"$ETCDIR/known_hosts"
	chmod 0640 "$ETCDIR/known_hosts"
fi

# Replace-or-append the marked cron line, so re-installs never duplicate it.
# /etc/crontab is the system crontab and has a user field on Linux and BSD
# alike — hence the explicit 'root' column.
tmp="$CRONTAB.net-sftp-forwarder.$$"
if [ -f "$CRONTAB" ]; then
	grep -F -v -- "$MARKER" "$CRONTAB" >"$tmp" || true
else
	: >"$tmp" # no system crontab yet: start from an empty one
fi
printf '* * * * * root %s/net-sftp-forwarder-run %s\n' "$LIBEXEC" "$MARKER" >>"$tmp"
install -m 0644 "$tmp" "$CRONTAB"
rm -f "$tmp"

echo 'Installed:'
echo "  $LIBEXEC/net-sftp-forwarder-run"
echo "  $ETCDIR/conf.d  (template: service.conf.sample)"
echo "  $ETCDIR/known_hosts"
echo "  one marked cron line in $CRONTAB"
echo 'Next: add a job (sudo make config, or copy the sample) and seed known_hosts.'
