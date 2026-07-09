# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mattia Cabrini
#
# Thin wrappers only; the logic lives in the Go program and install/*.sh.
# Works with both GNU make and BSD make.

GO = go
# -buildvcs=false keeps Go from stamping VCS metadata into the binary.
# `sudo make install` compiles inside a git tree owned by a non-root user,
# where Go's VCS probe aborts with "detected dubious ownership"; disabling it
# also makes the build independent of the surrounding checkout's git state.
GOBUILD = $(GO) build -buildvcs=false

all: build

build:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt: files need formatting:"; echo "$$out"; exit 1; fi; echo "ok: gofmt"
	mkdir -p build
	$(GOBUILD) -o build/net-sftp-forwarder-run ./cmd/net-sftp-forwarder-run

check:
	sh install/check.sh
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt: files need formatting:"; echo "$$out"; exit 1; fi; echo "ok: gofmt"
	$(GO) vet ./...
	$(GO) test ./...
	$(GOBUILD) -o /dev/null ./cmd/net-sftp-forwarder-run

config:
	sh install/config.sh

# install compiles like build but deliberately skips the gofmt gate:
# it runs under sudo, where gofmt may not be on root's PATH.
install:
	mkdir -p build
	$(GOBUILD) -o build/net-sftp-forwarder-run ./cmd/net-sftp-forwarder-run
	sh install/install.sh

uninstall:
	sh install/uninstall.sh

clean:
	rm -rf build

.PHONY: all build check config install uninstall clean
