
.PHONY: all
all: golangci-lint certstrap

# .PHONY to let go-build handle deps and rebuilds
.PHONY: golangci-lint
golangci-lint:
	go mod download github.com/golangci/golangci-lint
	go mod tidy
	go build github.com/golangci/golangci-lint/cmd/golangci-lint

# .PHONY to let go-build handle deps and rebuilds
.PHONY: certstrap
certstrap:
	go mod download github.com/square/certstrap
	go mod tidy
	go build github.com/square/certstrap

# .PHONY to let go-build handle deps and rebuilds
.PHONY: lipo
lipo:
	go mod download github.com/konoui/lipo
	go mod tidy
	go build github.com/konoui/lipo
