#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mattia Cabrini
#
# Uninstaller for net-sftp-forwarder: removes the marked cron line and the
# installed binary, but keeps /usr/local/etc/net-sftp-forwarder — the
# admin's configurations, keys and known_hosts survive a reinstall cycle.

set -eu

LIBEXEC=/usr/local/libexec/net-sftp-forwarder
ETCDIR=/usr/local/etc/net-sftp-forwarder
CRONTAB=/etc/crontab
MARKER='# net-sftp-forwarder' # must match install.sh

if [ "$(id -u)" -ne 0 ]; then
	echo 'uninstall.sh: must be run as root (try: sudo make uninstall)' >&2
	exit 1
fi

if [ -f "$CRONTAB" ] && grep -F -q -- "$MARKER" "$CRONTAB"; then
	tmp="$CRONTAB.net-sftp-forwarder.$$"
	grep -F -v -- "$MARKER" "$CRONTAB" >"$tmp" || true
	install -m 0644 "$tmp" "$CRONTAB"
	rm -f "$tmp"
	echo "Removed: marked cron line from $CRONTAB"
fi

if [ -d "$LIBEXEC" ]; then
	rm -rf "$LIBEXEC"
	echo "Removed: $LIBEXEC"
fi

echo "Kept:    $ETCDIR (configurations, keys, known_hosts)"
