
.PHONY: all
all: tkey-verification gen-signing-keypair

# .PHONY to let go-build handle deps and rebuilds
.PHONY: tkey-verification
tkey-verification:
	go build ./cmd/tkey-verification

# .PHONY to let go-build handle deps and rebuilds
.PHONY: gen-signing-keypair
gen-signing-keypair:
	go build ./cmd/gen-signing-keypair

.PHONY: clean
clean:
	rm -f tkey-verification gen-signing-keypair

.PHONY: lint
lint:
	$(MAKE) -C gotools
	./gotools/golangci-lint run
