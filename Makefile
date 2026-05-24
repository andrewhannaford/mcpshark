VERSION     ?= dev
LDFLAGS     := -ldflags "-s -w -X main.version=$(VERSION)"
BINARY      := dist/mcpshark
MAIN        := ./cmd/mcpshark

.PHONY: all build test lint clean setup release-dry

all: build

## setup: install dev dependencies (run once after cloning)
setup:
	go mod tidy
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

## build: compile mcpshark for the current platform
build:
	mkdir -p dist
	go build $(LDFLAGS) -o $(BINARY) $(MAIN)

## test: run all tests
test:
	go test -race ./...

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## run: build and print version (quick sanity check)
run: build
	./$(BINARY) version

## clean: remove build artifacts
clean:
	rm -rf dist/

## release-dry: run goreleaser in dry-run mode (requires goreleaser installed)
release-dry:
	goreleaser release --snapshot --clean

help:
	@grep -E '^## ' Makefile | sed 's/## //'
