#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mattia Cabrini
#
# Interactive creation of one net-sftp-forwarder service configuration
# (`sudo make config`). Assembles the fields, then offers two independent
# and entirely optional steps: generating the SSH key and testing the
# connection. This is the only part of the tool that runs the OpenSSH
# client programs (ssh-keygen, sftp), and only in those optional steps —
# the forwarder itself never needs them. The same result is always
# reachable by copying service.conf.sample by hand.

set -eu

NET_SFTP_FORWARDER_CONFDIR=${NET_SFTP_FORWARDER_CONFDIR:-/usr/local/etc/net-sftp-forwarder/conf.d}
NET_SFTP_FORWARDER_KNOWN_HOSTS=${NET_SFTP_FORWARDER_KNOWN_HOSTS:-/usr/local/etc/net-sftp-forwarder/known_hosts}

if [ "$(id -u)" -ne 0 ]; then
	echo 'config.sh: must be run as root (try: sudo make config)' >&2
	exit 1
fi

# ask PROMPT DEFAULT -> the reply, or DEFAULT when the reply is empty.
# Prompts on /dev/tty so it works even when stdin is not a terminal.
ask() {
	local reply
	if [ -n "$2" ]; then
		printf '%s [%s]: ' "$1" "$2" >/dev/tty
	else
		printf '%s: ' "$1" >/dev/tty
	fi
	IFS= read -r reply </dev/tty || reply=''
	printf '%s' "${reply:-$2}"
}

# confirm PROMPT -> true only when the user answers yes.
confirm() {
	case $(ask "$1" '') in
	[Yy]*) return 0 ;;
	*) return 1 ;;
	esac
}

# --- 1. Name the job ---------------------------------------------------------

name=''
while [ -z "$name" ]; do
	name=$(ask 'Job name' '')
	name=$(basename "$name" .conf)
	# The forwarder ignores dotfiles, so a leading-dot name would write a
	# configuration that never runs; basename can also yield '/' on odd input.
	case $name in
	.* | /)
		echo "A job name cannot start with '.' (the forwarder ignores dotfiles); try again." >&2
		name=''
		;;
	esac
done
conf="$NET_SFTP_FORWARDER_CONFDIR/$name.conf"

if [ -e "$conf" ] && ! confirm "$conf exists. Overwrite? [y/N]"; then
	echo 'Aborted; nothing written.'
	exit 1
fi

# --- 2. Gather the fields ----------------------------------------------------

# source, dst and key are required; insisting here beats writing a job
# that fails validation every minute. key's prompt has a non-empty
# default, so it needs no loop.
src=''
while [ -z "$src" ]; do
	src=$(ask 'Source directory (absolute path)' '')
done
dst=''
while [ -z "$dst" ]; do
	dst=$(ask 'Destination ([user@]host:/absolute/remote/dir)' '')
done
fuser=$(ask 'Owner-user pattern (empty = no constraint)' '')
fgroup=$(ask 'Owner-group pattern (empty = no constraint)' '')
key=$(ask 'SSH private key' "/usr/local/etc/net-sftp-forwarder/keys/${name}_ed25519")
port=$(ask 'SSH port (empty = 22)' '')
known=$(ask 'Per-job known_hosts (empty = use the global one)' '')

# --- 3. Optionally create the key --------------------------------------------

if confirm 'Create the SSH key now? [y/N]'; then
	if [ -f "$key" ]; then
		echo "Key $key already exists; skipping generation."
	else
		install -d -m 0700 "$(dirname "$key")"
		# Empty passphrase: the key is used unattended from cron.
		ssh-keygen -t ed25519 -N '' -C "net-sftp-forwarder $name@$(hostname)" -f "$key"
		chmod 0600 "$key"
	fi
	# An existing key may have lost its .pub; it can be rederived from the
	# private half so the printout below still works.
	if [ ! -f "$key.pub" ]; then
		ssh-keygen -y -f "$key" >"$key.pub" || rm -f "$key.pub"
	fi
	if [ -f "$key.pub" ]; then
		echo ''
		echo 'Public key:'
		cat "$key.pub"
		echo ''
		echo 'Hardened line for the destination account ~/.ssh/authorized_keys'
		echo '(a from="<source-address>" prefix tightens it further):'
		printf 'restrict %s\n' "$(cat "$key.pub")"
		echo ''
	else
		echo "Warning: $key.pub is missing and could not be derived;" >&2
		echo "print it later with: ssh-keygen -y -f $key" >&2
	fi
fi

# --- 4. Optionally test the connection ---------------------------------------

if confirm 'Test the connection now? [y/N]'; then
	echo 'Note: the test can only succeed once the public key is installed on the destination.'

	# Split dst the way the forwarder does (see splitDst in
	# internal/config/config.go): the first colon after the host separates
	# destination from remote directory; IPv6 hosts are bracketed.
	# The bracket branch applies only when the host part starts with '['
	# (with or without user@), as in the Go parser — a mere ']:' later in
	# the remote path must not trigger it.
	case $dst in
	\[*\]:* | *@\[*\]:*)
		ssh_dest=${dst%%]:*}]
		remote_dir=${dst#*]:}
		;;
	*:*)
		ssh_dest=${dst%%:*}
		remote_dir=${dst#*:}
		;;
	*)
		ssh_dest=$dst
		remote_dir=''
		;;
	esac

	kh=${known:-$NET_SFTP_FORWARDER_KNOWN_HOSTS}

	# accept-new records the host key while connecting, in the same format
	# the forwarder reads, so the service (strict by default) will verify
	# against it afterwards.
	if sftp ${port:+-P "$port"} -oBatchMode=yes -oStrictHostKeyChecking=accept-new \
		-oUserKnownHostsFile="$kh" -i "$key" -b - "$ssh_dest" <<SFTP
ls "$remote_dir"
SFTP
	then
		echo 'Connection test: OK.'
	else
		echo 'Connection test: FAILED (fix and re-run, or let cron retry once the job is in place).'
	fi
fi

# --- 5. Write the configuration ----------------------------------------------

install -d -m 0750 "$NET_SFTP_FORWARDER_CONFDIR"
tmp="$NET_SFTP_FORWARDER_CONFDIR/.$name.conf.tmp"

{
	printf '# net-sftp-forwarder job: %s\n' "$name"
	printf '# Created by make config; edit freely. See service.conf.sample.\n'
	printf 'source: %s\n' "$src"
	printf 'dst: %s\n' "$dst"
	printf 'file-user: %s\n' "$fuser"
	printf 'file-group: %s\n' "$fgroup"
	printf 'key: %s\n' "$key"
	if [ -n "$port" ]; then
		printf 'port: %s\n' "$port"
	fi
	if [ -n "$known" ]; then
		printf 'known-hosts: %s\n' "$known"
	fi
} >"$tmp"

chmod 0640 "$tmp"
mv "$tmp" "$conf"
echo "Wrote $conf"
