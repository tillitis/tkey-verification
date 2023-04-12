
.PHONY: all
all: show-pubkey tkey-verification

.PHONY:
install:
	install -Dm755 tkey-verification /usr/local/bin/tkey-verification

.PHONY: appbins-from-tags
appbins-from-tags:
	./build-appbins-from-tags.sh

# .PHONY to let go-build handle deps and rebuilds
.PHONY: show-pubkey
show-pubkey:
	go build ./cmd/show-pubkey
	@printf "Built ./show-pubkey\n"

# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-verification
tkey-verification:
	cp -af vendor-signing-pubkeys.txt ./internal/vendorsigning/vendor-signing-pubkeys.txt
	go build ./cmd/tkey-verification
	./tkey-verification --version

.PHONY: clean
clean:
	make -C apps clean
	rm -f internal/appbins/bins/*.bin
	rm -f internal/vendorsigning/vendor-signing-pubkeys.txt
	rm -f show-pubkey tkey-verification

.PHONY: lint
lint:
	$(MAKE) -C gotools golangci-lint
	GOOS=linux   ./gotools/golangci-lint run
	GOOS=windows ./gotools/golangci-lint run
	GOOS=darwin  ./gotools/golangci-lint run

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
