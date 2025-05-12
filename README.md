# sigstore-go

A client library for [Sigstore](https://www.sigstore.dev/), written in Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/sigstore/sigstore-go.svg)](https://pkg.go.dev/github.com/sigstore/sigstore-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/sigstore/sigstore-go)](https://goreportcard.com/report/github.com/sigstore/sigstore-go)
[![test results](https://github.com/sigstore/sigstore-go/actions/workflows/build.yml/badge.svg)](https://github.com/sigstore/sigstore-go/actions/workflows/build.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/sigstore-go/badge)](https://securityscorecards.dev/viewer/?uri=github.com/sigstore/sigstore-go)

Features:
- Signing and verification of [Sigstore bundles](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) compliant with Sigstore Client Spec
- Verification of raw Sigstore signatures by creating bundles for them (see [conformance tests](test/conformance/main.go) for example)
- Signing and verifying with a Timestamp Authority (TSA)
- Signing and verifying with Rekor (Artifact Transparency Log)
- Structured verification results including certificate metadata
- TUF support for fetching trusted root certificates and log keys
- Verification support for custom [trusted root](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto)
- Examples for signing and verifying artifacts

There is not built-in support for signing with a KMS or other bring-your-own-key; however you can easily add support by implementing your own version of the interface `pkg/sign/keys.go:Keypair`.

## Background

Sigstore already has a canonical Go client implementation, [cosign](https://github.com/sigstore/cosign), which was developed with a focus on container image signing/verification. It has a rich CLI and a long legacy of features and development. `sigstore-go` is a more minimal and friendly API for integrating Go code with Sigstore, with a focus on the newly specified data structures in [sigstore/protobuf-specs](https://github.com/sigstore/protobuf-specs). `sigstore-go` attempts to minimize the dependency tree for simple signing and verification tasks, omitting KMS support and container image verification, and we intend to refactor parts of `cosign` to depend on `sigstore-go`.

## Status

`sigstore-go` is considered stable and ready for production use. It passes the [`sigstore-conformance`](https://github.com/sigstore/sigstore-conformance) signing and verification test suite.

## Documentation and examples

Documentation is found in the [`docs`](./docs) subdirectory and on [pkg.go.dev](https://pkg.go.dev/github.com/sigstore/sigstore-go).

See the [examples directory](./examples/README.md) for examples of how to use this library.

Note that the CLI examples are to demonstrate how to use the library, and not intended as a fully-featured Sigstore CLI like [cosign](https://github.com/sigstore/cosign).

## Requirements

[Tested](https://github.com/sigstore/sigstore-go/blob/main/.github/workflows/build.yml) with:

- Unix-compatible OS and Windows
- [Go 1.23+](https://go.dev/doc/install)

Note that we do not provide built versions of this library, but you can see what architectures your version of `go` supports with `go tool dist list`.

## Testing

Tests are invoked using the standard Go testing framework. A helper exists in the Makefile also.

```shell
$ make test
```

## Support

Bug reports are welcome via issues and questions are welcome via discussion. Please refer to [SUPPORT.md](./SUPPORT.md) for details.
This project is provided as-is.

## Security

Should you discover any security issues, please refer to sigstore's [security
process](https://github.com/sigstore/.github/blob/main/SECURITY.md)
