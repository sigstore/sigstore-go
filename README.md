# sigstore-verifier

An experimental verifier for Sigstore, created by the Package Security Team

This can be thought of as a prototype for `sigstore-go`, a general purpose Go library for Sigstore.

## Usage

This library is primarily intended to be used a dependency for Go applications that need support for verifying Sigstore bundles, but it does include a small verifier CLI that can be used for testing.

### Library

TODO: Library usage example code. For now, see the code in [the CLI command](./cmd/sigstore-verifier/main.go) for a library usage example.

### CLI

To use the example CLI, invoke with `go run` like so:

```shell
go run ./cmd/sigstore-verifier examples/bundle-provenance.json
```

Alternatively, you can install a binary of the CLI like so:

```shell
go install ./cmd/sigstore-verifier
sigstore-verifier examples/bundle-provenance.json
```

## Testing

Tests are invoked using the standard Go testing framework. A helper exists in the Makefile also.

```shell
    make test
```

## Example bundles

### examples/bundle-provenance.json

This came from https://www.npmjs.com/package/sigstore/v/1.3.0/provenance, with the outermost "bundle" key stripped off.

## examples/bundle-github-staging-sigstorejs1.3.0.json

This bundle is created by sigstore-js by attesting the file `examples/statement-provenance-sigstorejs1.3.0.json` using the GitHub staging instances of Fulcio and TSA.

In case this needs to be regenerated (in the event of key rotation), the following command will produce the equivalent file:

```shell
# Install sigstore-js CLI
npm install -g @sigstore/cli
# Sign an attestation. Note that you must be connected to the GitHub VPN in order to reach these services.
sigstore attest --fulcio-url=https://fulcio-staging.service.iad.github.net --tsa-server-url=https://timestamp-authority-staging.service.iad.github.net --no-tlog-upload examples/statement-provenance-sigstorejs1.3.0.json | jq > examples/bundle-github-staging-sigstorejs1.3.0.json
```

To verify this attestation using the GitHub staging trusted root, issue the following command:

```shell
go run cmd/sigstore-verifier/main.go -requireTSA -trustedrootJSONpath examples/trusted-root-github-staging.json examples/bundle-github-staging-sigstorejs1.3.0.json
```
