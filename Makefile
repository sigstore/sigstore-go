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

.PHONY: all
all: build-examples

.PHONY: build-examples
build-examples:
	go build -C ./examples/sigstore-go-signing -o sigstore-go-signing .
	go build -C ./examples/sigstore-go-verification -o sigstore-go-verification .
	go build -C ./examples/oci-image-verification -o oci-image-verification .

.PHONY: test
test:
	go test ./...

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run
