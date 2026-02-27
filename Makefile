.PHONY: build test clean run lint

BINARY := namek
VERSION ?= dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/namek/

test:
	go test -race -count=1 ./...

clean:
	rm -rf bin/

run: build
	./bin/$(BINARY) -config config.yaml

lint:
	golangci-lint run ./...
