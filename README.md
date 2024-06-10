# sigstore-go

A client library for [Sigstore](https://www.sigstore.dev/), written in Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/sigstore/sigstore-go.svg)](https://pkg.go.dev/github.com/sigstore/sigstore-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sigstore/sigstore-go)](https://goreportcard.com/report/github.com/sigstore/sigstore-go)
[![e2e-tests](https://github.com/sigstore/sigstore-go/actions/workflows/build.yml/badge.svg)](https://github.com/sigstore/sigstore-go/actions/workflows/build.yml)

Features:
- Signing and verification of [Sigstore bundles](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) compliant with Sigstore Client Spec
- Verification of raw Sigstore signatures by creating bundles for them (see [conformance tests](cmd/conformance/main.go) for example)
- Signing and verifying with a Timestamp Authority (TSA)
- Signing and verifying (offline or online) with Rekor (Artifact Transparency Log)
- Structured verification results including certificate metadata
- TUF support
- Verification support for custom [trusted root](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto)
- Basic CLI and examples

There is not built-in support for signing with a KMS or other bring-your-own-key; however you can easily add support by implementing your own version of the interface `pkg/sign/keys.go:Keypair`.

For an example of how to use this library, see [the verification documentation](./docs/verification.md), the CLI [cmd/sigstore-go](./cmd/sigstore-go/main.go), or the CLI examples below. Note that the CLI is to demonstrate how to use the library, and not intended as a fully-featured Sigstore CLI like [cosign](https://github.com/sigstore/cosign).

## Background

Sigstore already has a canonical Go client implementation, [cosign](https://github.com/sigstore/cosign), which was developed with a focus on container image signing/verification. It has a rich CLI and a long legacy of features and development. `sigstore-go` is a more minimal and friendly API for integrating Go code with Sigstore, with a focus on the newly specified data structures in [sigstore/protobuf-specs](https://github.com/sigstore/protobuf-specs). `sigstore-go` attempts to minimize the dependency tree for simple signing and verification tasks, omitting KMS support and container image verification, and we intend to refactor parts of `cosign` to depend on `sigstore-go`.

## Status

`sigstore-go` is currently beta, and may have minor API changes before the 1.0.0 release. It does however pass the [`sigstore-conformance`](https://github.com/sigstore/sigstore-conformance) signing and verification test suite, and correctness is taken very seriously.

## Documentation

Documentation is found in the [`docs`](./docs) subdirectory.

## Requirements

- Unix-compatible OS
- [Go 1.21](https://go.dev/doc/install)

## Installation

You can use the CLI with `go run` as in the below examples, or compile/install the `sigstore-go` CLI:

```shell
$ make install
```
## Examples

```shell
$ go run cmd/sigstore-go/main.go \
  -artifact-digest 76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751 \
  -artifact-digest-algorithm sha512 \
  -expectedIssuer https://token.actions.githubusercontent.com \
  -expectedSAN https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main \
  examples/bundle-provenance.json
Verification successful!
{
   "version": 20230823,
   "statement": {
      "_type": "https://in-toto.io/Statement/v0.1",
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "subject": ...
    },
    ...
}
```

You can also specify a TUF root with something like `-tufRootURL tuf-repo-cdn.sigstore.dev`.

Alternatively, you can install a binary of the CLI like so:

```shell
$ go install ./cmd/sigstore-go
$ sigstore-go ...
```

## Testing

Tests are invoked using the standard Go testing framework. A helper exists in the Makefile also.

```shell
$ make test
```

## Example bundles

### examples/bundle-provenance.json

This came from https://www.npmjs.com/package/sigstore/v/1.3.0/provenance, with the outermost "bundle" key stripped off.

## Support

Bug reports are welcome via issues and questions are welcome via discussion. Please refer to [SUPPORT.md](./SUPPORT.md) for details.
This project is provided as-is.
