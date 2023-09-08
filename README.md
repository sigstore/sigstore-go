# sigstore-verifier

A Go client library for [Sigstore](https://www.sigstore.dev/)

This library focused on verifying Sigstore bundles, although it can also verify signature files by creating a bundle for them.

It supports a wide variety of use cases through the [verification options](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_verification.proto).

For an example of how to use this library, see [cmd/sigstore-verifier](./cmd/sigstore-verifier/main.go).

## Examples

```bash
$ go run cmd/sigstore-verifier/main.go -trustedrootJSONpath examples/trusted-root-public-good.json examples/bundle-provenance.json
Verification successful!
```

```bash
$ go run cmd/sigstore-verifier/main.go -tufRootURL tuf-repo-cdn.sigstore.dev examples/bundle-provenance.json
Verification successful!
```

Alternatively, you can install a binary of the CLI like so:

```shell
$ go install ./cmd/sigstore-verifier
$ sigstore-verifier examples/bundle-provenance.json
```

## Testing

Tests are invoked using the standard Go testing framework. A helper exists in the Makefile also.

```shell
$ make test
```

## Example bundles

### examples/bundle-provenance.json

This came from https://www.npmjs.com/package/sigstore/v/1.3.0/provenance, with the outermost "bundle" key stripped off.

## License

This project is licensed under the terms of the MIT open source license. Please refer to [MIT](./LICENSE.txt) for the full terms.

## Support

Bug reports are welcome via issues and questions are welcome via discussion. Please refer to [SUPPORT.md](./SUPPORT.md) for details.
This project is provided as-is.
