
.PHONY: all
all: show-pubkey tkey-verification

.PHONY:
install:
	install -Dm755 tkey-verification /usr/local/bin/tkey-verification

# .PHONY to let go-build handle deps and rebuilds
.PHONY: show-pubkey
show-pubkey:
	go build ./cmd/show-pubkey

# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-verification
tkey-verification:
	cp -a "$(SIGNING_PUBKEYS_FILE)" ./internal/vendorsigning/vendor-signing-pubkeys.txt
	@[ -n "$(DEVICE_SIGNERAPP_TAG)" ] || { printf "DEVICE_SIGNERAPP_TAG not set\n"; exit 1; }
	go build -ldflags "-X main.Tag=$(DEVICE_SIGNERAPP_TAG)" ./cmd/tkey-verification

.PHONY: clean
clean:
	rm -f show-pubkey tkey-verification

.PHONY: lint
lint:
	$(MAKE) -C gotools golangci-lint
	./gotools/golangci-lint run

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
