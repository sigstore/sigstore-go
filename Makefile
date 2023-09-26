.PHONY: build
build:
	go build ./cmd/sigstore-go
	go build -o conformance ./cmd/conformance

.PHONY: test
test:
	go test ./...

.PHONY: install
install:
	go install ./cmd/...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run
