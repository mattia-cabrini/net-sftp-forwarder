// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

// Command net-sftp-forwarder-run is the cron entry point of
// net-sftp-forwarder. Once a minute it takes the run lock, walks every
// *.conf job in the configuration directory, and forwards each job's
// eligible files over SFTP (see README.md). Outcomes go to syslog; an idle
// minute produces no output at all. The environment is the whole interface
// — there are no command-line flags:
//
//	NET_SFTP_FORWARDER_CONFDIR      job directory      (default /usr/local/etc/net-sftp-forwarder/conf.d)
//	NET_SFTP_FORWARDER_KNOWN_HOSTS  global known_hosts (default /usr/local/etc/net-sftp-forwarder/known_hosts)
//	NET_SFTP_FORWARDER_LOCK         run-lock file      (default /var/run/net-sftp-forwarder.lock)
//	NET_SFTP_FORWARDER_TAG          syslog tag         (default net-sftp-forwarder)
//	NET_SFTP_FORWARDER_STRICT       host-key policy: yes (default) or accept-new
package main

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"net-sftp-forwarder/internal/config"
	"net-sftp-forwarder/internal/hostkey"
	"net-sftp-forwarder/internal/match"
	"net-sftp-forwarder/internal/transfer"
)

func main() {
	os.Exit(run())
}

// run is main separated from os.Exit so deferred cleanups actually execute.
// It exits 0 on every normal path, job failures included (those are logged,
// and cron reacts to output, not exit codes); non-zero means the run could
// not even start.
func run() int {
	confDir := cmp.Or(os.Getenv("NET_SFTP_FORWARDER_CONFDIR"), "/usr/local/etc/net-sftp-forwarder/conf.d")
	knownHosts := cmp.Or(os.Getenv("NET_SFTP_FORWARDER_KNOWN_HOSTS"), "/usr/local/etc/net-sftp-forwarder/known_hosts")
	lockPath := cmp.Or(os.Getenv("NET_SFTP_FORWARDER_LOCK"), "/var/run/net-sftp-forwarder.lock")
	tag := cmp.Or(os.Getenv("NET_SFTP_FORWARDER_TAG"), "net-sftp-forwarder")
	strict := cmp.Or(os.Getenv("NET_SFTP_FORWARDER_STRICT"), "yes")

	log := newSink(tag)
	defer log.Close()

	policy, ok := hostkey.ParsePolicy(strict)
	if !ok {
		log.Warningf("config warning: NET_SFTP_FORWARDER_STRICT='%s' is neither 'yes' nor 'accept-new'; using 'yes'", strict)
	}

	// The lock keeps a slow transfer from colliding with the next minute's
	// invocation. flock is released by the kernel when the process exits —
	// even on SIGKILL — so there is no stale-lock failure mode and no signal
	// handling. The lock file is never unlinked: unlinking would race with a
	// concurrent locker holding the old inode.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		log.Errf("cannot open lock file %s: %v", lockPath, err)
		return 1
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK {
			return 0 // a previous run is still transferring; skip this minute
		}
		log.Errf("cannot lock %s: %v", lockPath, err)
		return 1
	}

	entries, err := os.ReadDir(confDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0 // no configuration directory: nothing to do
		}
		log.Errf("config error: %s: %v", confDir, err)
		return 1
	}
	for _, e := range entries {
		name := e.Name()
		// Only *.conf files are jobs; the shipped .sample, dotfiles and
		// editor backups all fall through, like the original *.conf glob.
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		runJob(log, filepath.Join(confDir, name), knownHosts, policy)
	}
	return 0
}

// runJob executes one service configuration end to end. All outcomes are
// logged rather than returned: jobs are independent, and a failure here
// must not stop the caller's loop over the remaining jobs.
func runJob(log *sink, confPath, defaultKnownHosts string, policy hostkey.Policy) {
	name := filepath.Base(confPath)
	job, warnings, err := config.Load(confPath, defaultKnownHosts)
	for _, w := range warnings {
		log.Warningf("config warning: %s: %s", name, w)
	}
	if err != nil {
		log.Errf("config error: %s: %v", name, err)
		return
	}

	entries, err := os.ReadDir(job.Source)
	if err != nil {
		log.Errf("config error: %s: reading source: %v", name, err)
		return
	}

	// The SSH session is opened lazily, on the first eligible file, and
	// shared by the rest of the job: an idle job never touches the network,
	// and a busy one pays for a single handshake. os.ReadDir sorts, so
	// files are processed in a deterministic lexical order.
	var session *transfer.Session
	defer func() {
		if session != nil {
			session.Close()
		}
	}()

	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue // directories, symlinks, sockets, ... are never eligible
		}
		info, err := e.Info()
		if err != nil {
			continue // vanished since ReadDir; the next run will see it
		}
		owner, group, err := match.Owner(info)
		if err != nil {
			log.Warningf("config warning: %s: cannot determine owner of '%s': %v", name, e.Name(), err)
			continue
		}
		if !match.Matches(job.UserRe, owner) || !match.Matches(job.GroupRe, group) {
			continue // not eligible; deliberately unlogged — it would bury the signal
		}

		if session == nil {
			signer, err := transfer.LoadKey(job.KeyPath)
			if err != nil {
				log.Errf("config error: %s: %v", name, err)
				return
			}
			checker, err := hostkey.New(job.KnownHosts, policy)
			if err != nil {
				log.Errf("config error: %s: %v", name, err)
				return
			}
			s, err := transfer.Dial(job.SSHUser, job.Host, job.Port, signer, checker)
			if err != nil {
				log.Errf("failed: connect %s (config=%s): %v", job.Dest, name, err)
				return
			}
			session = s
		}

		local := filepath.Join(job.Source, e.Name())
		if err := session.Forward(local, job.RemoteDir); err != nil {
			// One failure usually means the remote is unreachable: stop this
			// job (the file stays and is retried next minute), let the other
			// jobs run.
			log.Errf("failed: %s -> %s (config=%s): %v", e.Name(), job.Dest, name, err)
			return
		}
		if err := os.Remove(local); err != nil {
			// The remote copy exists but the local one would not go away;
			// stop before the next minute forwards duplicates blindly.
			log.Errf("failed: %s -> %s (config=%s): removing local file after transfer: %v", e.Name(), job.Dest, name, err)
			return
		}
		log.Noticef("forwarded: %s -> %s:%s (config=%s, user=%s, group=%s)",
			e.Name(), job.Dest, job.RemoteDir, name, owner, group)
	}
}
