# sigstore-go

A client library for [Sigstore](https://www.sigstore.dev/), written in Go.

Features:
- Verification of [Sigstore bundles](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) compliant with Sigstore Client Spec
- Verification of raw Sigstore signatures by creating bundles for them (see [conformance tests](cmd/conformance/main.go) for example)
- Timestamp Authority (TSA) verification
- Rekor (Artifact Transparency Log) verificaton (offline or online)
- Structured verification results including certificate metadata
- TUF support
- Support for custom [trusted root](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto)
- Basic CLI

For an example of how to use this library, see [cmd/sigstore-go](./cmd/sigstore-go/main.go), or see the CLI examples below.

## Background

Sigstore already has a canonical Go client implementation, [cosign](https://github.com/sigstore/cosign), which was developed with a focus on container image signing/verification. It has a rich CLI and a long legacy of features and development. `sigstore-go` is a more minimal and friendly API for integrating Go code with Sigstore, with a focus on the newly specified data structures in [sigstore/protobuf-specs](https://github.com/sigstore/protobuf-specs).

## Requirements

- Unix-compatible OS
- [Go 1.21](https://go.dev/doc/install)

## Installation

You can use the CLI with `go run` as in the below examples, or compile/install the `sigstore-go` CLI:

```bash
$ make install
```
## Examples

```bash
$ go run cmd/sigstore-go/main.go -trustedrootJSONpath examples/trusted-root-public-good.json examples/bundle-provenance.json
Verification successful!
```

```bash
$ go run cmd/sigstore-go/main.go -tufRootURL tuf-repo-cdn.sigstore.dev examples/bundle-provenance.json
Verification successful!
```

Alternatively, you can install a binary of the CLI like so:

```shell
$ go install ./cmd/sigstore-go
$ sigstore-go examples/bundle-provenance.json
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
