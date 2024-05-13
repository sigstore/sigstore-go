# Copyright 2023 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION := `git describe --tags`
LDFLAGS = -ldflags "-X main.Version=$(VERSION)"

.PHONY: all
all: build build-examples

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/sigstore-go
	go build $(LDFLAGS) -o conformance ./cmd/conformance

.PHONY: build-examples
build-examples:
	go build -C $(LDFLAGS) -o oci-image-verification ./examples/oci-image-verification
	go build $(LDFLAGS) -o sigstore-signing ./examples/signing

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
