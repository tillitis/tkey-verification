shasum = sha512sum
CGO = 0

.PHONY: all
all: tkey-verification

APP_VERSION ?= $(shell git describe --dirty --always | sed -n "s/^v\(.*\)/\1/p")
# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-verification
tkey-verification:
	CGO_ENABLED=$(CGO) go build -ldflags "-X main.version=$(APP_VERSION)" -trimpath -buildvcs=false ./cmd/tkey-verification
	./tkey-verification --version

.PHONY: podman
podman:
	podman run --arch=amd64 --rm --mount type=bind,source=$(CURDIR),target=/src -w /src -it ghcr.io/tillitis/tkey-builder:4 make -j

.PHONY: check-digests
check-digests:
	cd cmd/tkey-verification/bins && \
	$(shasum) -c signer-v1.0.1.bin.sha512 && \
	$(shasum) -c verisigner-v0.0.3.bin.sha512

doc/tkey-verification.1: doc/tkey-verification.scd
	scdoc < $^ > $@

.PHONY: clean
clean:
	rm -f tkey-verification

.PHONY: lint
lint:
	golangci-lint run

.PHONY: certs
certs:
	$(MAKE) -C gotools certstrap
	./gotools/certstrap --depot-path certs init --passphrase="" --common-name=tillitis

	# To deploy the tkey-verification server part (that runs the
	# serve-signer command) on a different machine, you need to add the
	# machine's IP address (or domain) to the following certificate
	# request. Adding for example the following at the end of the command
	# line: --ip=192.168.122.20
	./gotools/certstrap --depot-path certs request-cert --passphrase="" --common-name=server --domain=localhost
	./gotools/certstrap --depot-path certs sign --CA=tillitis server

	./gotools/certstrap --depot-path certs request-cert --passphrase="" --common-name=client
	./gotools/certstrap --depot-path certs sign --CA=tillitis client
