# net-sftp-forwarder

Copyright (c) 2026 Mattia Cabrini
SPDX-License-Identifier: MIT

A small, generic file mover for GNU/Linux and BSD. It watches one or more source
directories and forwards eligible files to remote hosts over SSH, once a minute,
driven entirely by configuration. Each configuration file is one transfer job.
A file is forwarded only when its owner user and group match the patterns you
set; on success the local file is removed, so this is a move, not a copy.

Delivery uses SFTP, so it works against stock `sshd` with nothing installed on
the far side — including restricted accounts with a `nologin` shell and a forced
`internal-sftp` command.

## Install

```
git clone <repo> net-sftp-forwarder
cd net-sftp-forwarder
make check          # optional: checks the scripts and the Go code
sudo make install   # builds the forwarder, installs it and the cron entry
```

`make install`:

- builds the forwarder and installs the binary into
  `/usr/local/libexec/net-sftp-forwarder`;
- creates the configuration directory `/usr/local/etc/net-sftp-forwarder/conf.d` and drops a
  documented `service.conf.sample` there;
- creates an empty `/usr/local/etc/net-sftp-forwarder/known_hosts`; and
- adds one marked line to `/etc/crontab` that runs the forwarder every minute.

It is safe to re-run: it updates everything in place.

```
sudo make uninstall   # removes the binary and the cron entry; keeps your configs
```

## Requirements

- To build: the Go toolchain (1.25 or later). Nothing Go-related is needed at
  runtime — the installed binary is self-contained.
- A POSIX `/bin/sh` for the install scripts (works with `dash` on Linux and
  the base `sh` on BSD).
- The OpenSSH client tools only where noted: `ssh-keygen` and `sftp` for
  `make config`'s optional key-generation and connection-test steps, and
  `ssh-keyscan` for seeding host keys (see "Host keys" below) — the
  forwarder itself never runs any of them.
- Nothing on the remote host beyond a running `sshd` with the SFTP subsystem
  (the default).

## Configure

A job is a `*.conf` file in `/usr/local/etc/net-sftp-forwarder/conf.d`. Add a job by copying the
sample and editing it; remove a job by deleting its file. Every `*.conf` there is
run, independently, once a minute.

The quickest way to create one is `make config`, which walks you through the
fields and then, if you want, generates the SSH key and prints the public key to
add on the destination, and tests the connection — both steps optional:

```
sudo make config
```

Or copy the sample and edit it by hand:

```
sudo cp /usr/local/etc/net-sftp-forwarder/conf.d/service.conf.sample \
        /usr/local/etc/net-sftp-forwarder/conf.d/myjob.conf
sudo $EDITOR /usr/local/etc/net-sftp-forwarder/conf.d/myjob.conf
```

A configuration has five fields (a `#` starts a comment to end of line):

```
source:      /var/spool/example/out                     # dir whose files are sent
dst:         user@remote.example.org:/var/spool/in      # [user@]host:/remote/dir
file-user:   ^(app|deploy)$                             # owner user must match (regexp)
file-group:  ^staff$                                    # owner group must match (regexp)
key:         /usr/local/etc/net-sftp-forwarder/keys/example_ed25519     # SSH private key, mode 0600
```

- **source** — the directory to scan (top level only; regular files only).
- **dst** — the remote target, split on the first colon into an SSH destination
  (which may carry `user@`; without it the user defaults to `root`) and an
  absolute remote directory. Write IPv6 literals in brackets
  (`user@[2001:db8::1]:/dir`); for a non-standard port set the optional
  `port:` key. The SSH client configuration (`~/.ssh/config`) is not read, so
  `Host` aliases do not apply here.
- **file-user** / **file-group** — regular expressions (Go/RE2 syntax) matched
  against the file's owner user and group. The match is anchored and
  full-string, so `log` does not match `catalog`. Leave a field empty to
  impose no constraint. A uid or gid with no name on the system is matched
  by its decimal number instead, so `^1001$` still catches files owned by
  an unmapped (for example, deleted) user.
- **key** — the SSH private key for this job. Keep it mode `0600`; the
  forwarder refuses keys with wider permissions, and passphrase-protected
  keys are unsupported (it runs unattended).

Optionally, a job may set `known-hosts:` to use a different `known_hosts` file
than the global one, and `port:` for a non-standard SSH port (default 22).

### Host keys

The forwarder verifies the remote host key (`StrictHostKeyChecking=yes`) against
`/usr/local/etc/net-sftp-forwarder/known_hosts`. Seed it once per remote so connections do not
fail closed:

```
sudo sh -c 'ssh-keyscan remote.example.org >> /usr/local/etc/net-sftp-forwarder/known_hosts'
```

Scan without `-t` so every key type the host offers gets pinned: client and
server negotiate a single host-key algorithm per connection, and a host
pinned with only one type would look like a key conflict if the negotiation
ever picks another.

For first-run convenience you may relax this by running with
`NET_SFTP_FORWARDER_STRICT=accept-new`, but pinning host keys ahead of time is the safer habit.

## How it works

Cron runs `net-sftp-forwarder-run` every minute. It takes a lock so runs never overlap, then
walks each `*.conf` in the config directory. For every regular file in a job's
`source`, it reads the file's owner user and group and checks them against the
job's patterns. A job with eligible files opens one SSH connection and reuses
it for all of them; a job with none stays off the network entirely. An
eligible file is uploaded to a temporary name on the remote — a leading-dot
`.part` file, invisible to a consumer's globs — and then renamed to its final
name in a single SFTP operation, so the file appears atomically and a consumer
never sees it half-written. A successful transfer removes the local file. A
failure leaves the file in place to be retried next minute and stops the rest
of that job, on the assumption the remote is unreachable; other jobs still
run.

Outcomes are written to syslog under the tag `net-sftp-forwarder` (on BSD, `/var/log/messages`):
a `forwarded:` line naming the file, destination, and matched owner, a
`failed:` line carrying the underlying error, or a `config error:` line for a
job that had to be skipped; ignored oddities such as an unknown key get a
`config warning:` line. Idle minutes are silent.

Producers that write into a `source` directory should deposit atomically (write
elsewhere, then rename into place), so the forwarder never picks up a
half-written file.

## Environment

The forwarder has no command-line flags; the environment is its whole
interface, and every variable has a sane default:

```
NET_SFTP_FORWARDER_CONFDIR      job directory      (default /usr/local/etc/net-sftp-forwarder/conf.d)
NET_SFTP_FORWARDER_KNOWN_HOSTS  global known_hosts (default /usr/local/etc/net-sftp-forwarder/known_hosts)
NET_SFTP_FORWARDER_LOCK         run-lock file      (default /var/run/net-sftp-forwarder.lock)
NET_SFTP_FORWARDER_TAG          syslog tag         (default net-sftp-forwarder)
NET_SFTP_FORWARDER_STRICT       host-key policy    (yes, the default, or accept-new)
```

## Limitations

Not recursive. Every eligible file is sent whole — no delta transfer, no
resume. A forwarded file is not archived locally; a successful send removes
it. The SSH client configuration (`~/.ssh/config`) is never read, and
passphrase-protected keys are unsupported. Configuration values cannot
contain `#` (it starts a comment); filenames in `source` carry no such
restriction — spaces and quotes are fine.

## License

MIT. See `LICENSE`.