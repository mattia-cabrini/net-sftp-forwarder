# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Mattia Cabrini
#
# Thin wrappers only; the logic lives in the Go program and install/*.sh.
# Works with both GNU make and BSD make.

GO = go

all: build

build:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt: files need formatting:"; echo "$$out"; exit 1; fi; echo "ok: gofmt"
	mkdir -p build
	$(GO) build -o build/net-sftp-forwarder-run ./cmd/net-sftp-forwarder-run

check:
	sh install/check.sh
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt: files need formatting:"; echo "$$out"; exit 1; fi; echo "ok: gofmt"
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) build -o /dev/null ./cmd/net-sftp-forwarder-run

config:
	sh install/config.sh

# install compiles like build but deliberately skips the gofmt gate:
# it runs under sudo, where gofmt may not be on root's PATH.
install:
	mkdir -p build
	$(GO) build -o build/net-sftp-forwarder-run ./cmd/net-sftp-forwarder-run
	sh install/install.sh

uninstall:
	sh install/uninstall.sh

clean:
	rm -rf build

.PHONY: all build check config install uninstall clean
