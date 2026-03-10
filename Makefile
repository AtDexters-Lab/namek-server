.PHONY: build test clean run lint dev-deps dev dev-down test-integration

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

dev-deps:
	docker compose -f deploy/docker-compose.dev.yml up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@echo "Fetching Pebble CA cert..."
	@mkdir -p deploy/pebble
	@for i in 1 2 3 4 5; do \
		curl -sf https://localhost:15000/roots/0 -k -o deploy/pebble/pebble.minica.pem && break; \
		echo "  Pebble not ready, retrying ($$i/5)..."; \
		sleep 2; \
	done
	@test -s deploy/pebble/pebble.minica.pem || (echo "ERROR: Failed to fetch Pebble CA cert" && exit 1)
	@echo "Initializing software TPM..."
	@go run ./cmd/swtpm-init
	@echo "Dev dependencies ready"

dev: build
	./bin/$(BINARY) -config config.dev.yaml

dev-down:
	docker compose -f deploy/docker-compose.dev.yml down -v

test-integration:
	go test -tags=integration -v -count=1 -timeout=120s ./tests/integration/
