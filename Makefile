IMAGE   ?= ghcr.io/0xbrdn/podwarden
VERSION ?= 0.2.0
CLUSTER ?= podwarden-lab

.PHONY: help build test cover vet lint docker kind-load demo clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build binaries into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/podwarden ./cmd/podwarden
	CGO_ENABLED=0 go build -trimpath -o bin/pwverify ./cmd/pwverify

test: ## Run unit tests with the race detector
	go test -race -count=1 ./...

cover: ## Run tests and print coverage
	go test -race -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

vet: ## go vet
	go vet ./...

lint: ## golangci-lint (must be installed)
	golangci-lint run ./...

docker: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

kind-load: docker ## Load the image into the kind lab cluster
	kind load docker-image $(IMAGE):$(VERSION) --name $(CLUSTER)

demo: ## Run the attack simulation
	./demo/simulate_attack.sh

clean: ## Remove build artifacts
	rm -rf bin coverage.out
