// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Mattia Cabrini

package main

import (
	"fmt"
	"log/syslog"
	"os"
	"strings"
)

// sink delivers one-line outcome messages to syslog under the configured
// tag, falling back to stderr when syslog is unreachable — cron then mails
// the lines to root, which is the right failure mode for a broken syslog.
type sink struct {
	w *syslog.Writer // nil when syslog could not be reached
}

func newSink(tag string) *sink {
	w, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_USER, tag)
	if err != nil {
		return &sink{}
	}
	return &sink{w: w}
}

func (s *sink) Close() {
	if s.w != nil {
		s.w.Close()
	}
}

func (s *sink) Infof(format string, a ...any)    { s.emit((*syslog.Writer).Info, format, a...) }
func (s *sink) Warningf(format string, a ...any) { s.emit((*syslog.Writer).Warning, format, a...) }
func (s *sink) Errf(format string, a ...any)     { s.emit((*syslog.Writer).Err, format, a...) }

// emit formats the message, collapses line breaks so a multi-line error
// cannot split a log entry, and delivers it at the severity selected by
// send.
func (s *sink) emit(send func(*syslog.Writer, string) error, format string, a ...any) {
	m := fmt.Sprintf(format, a...)
	m = strings.ReplaceAll(m, "\n", " ")
	m = strings.ReplaceAll(m, "\r", " ")
	if s.w == nil || send(s.w, m) != nil {
		fmt.Fprintln(os.Stderr, m)
	}
}
