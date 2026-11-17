BIN := bin
VERSION ?= 1.0.0
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build refserver fmt vet lint test race check clean

all: check build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BIN)/seyon ./cmd/seyon

refserver:
	go build -o $(BIN)/refserver ./lab/refserver

fmt:
	gofmt -l -w .

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	go test ./...

race:
	go test -race ./...

# The mandatory per-phase quality gate, runnable in one command.
check: vet lint test

clean:
	rm -rf $(BIN)
