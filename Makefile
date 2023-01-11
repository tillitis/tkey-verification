# TODO we should keep our signing pubkey committed
# SIGNING_PUBKEY ?= ./test-signing-tkey.pub

.PHONY: all
all: tkey-verification

.PHONY:
install:
	install -Dm755 tkey-verification /usr/local/bin/tkey-verification

# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-verification
tkey-verification:
	cp -a $(SIGNING_PUBKEY) ./cmd/tkey-verification/signing-tkey.pub
	go build ./cmd/tkey-verification

.PHONY: clean
clean:
	rm -f tkey-verification

.PHONY: lint
lint:
	$(MAKE) -C gotools golangci-lint
	./gotools/golangci-lint run

.PHONY: certs
certs:
	$(MAKE) -C gotools certstrap
	./gotools/certstrap --depot-path certs init --passphrase="" --common-name=tillitis

	./gotools/certstrap --depot-path certs request-cert --passphrase="" --domain=localhost
	./gotools/certstrap --depot-path certs sign --CA=tillitis localhost

	./gotools/certstrap --depot-path certs request-cert --passphrase="" --domain=client
	./gotools/certstrap --depot-path certs sign --CA=tillitis client
