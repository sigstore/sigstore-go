export GOPROXY = https://goproxy.githubapp.com/mod,https://proxy.golang.org/,direct
export GOPRIVATE =
export GONOPROXY =
export GONOSUMDB = github.com/github/*

.PHONY: build
build:
	go build ./cmd/sigstore-verifier
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
