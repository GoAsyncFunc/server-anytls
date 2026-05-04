VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.Version=$(VERSION)

fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write -s standard -s "prefix(github.com/GoAsyncFunc/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@latest
	go install -v github.com/daixiang0/gci@latest

lint:
	GOOS=linux golangci-lint run
	GOOS=windows golangci-lint run
	GOOS=darwin golangci-lint run
	GOOS=freebsd golangci-lint run

lint_install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

test:
	go test -race -coverprofile=coverage.out ./...

build:
	@mkdir -p build
	go build -v -trimpath -ldflags "$(LDFLAGS)" -o build/anytls-node ./cmd/server

clean:
	rm -rf build coverage.out

.PHONY: fmt fmt_install lint lint_install test build clean
