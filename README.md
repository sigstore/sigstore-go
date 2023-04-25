# sigstore-verifier

An experimental verifier for Sigstore, created by the Package Security Team

This can be thought of as a prototype for `sigstore-go`, a general purpose Go library for Sigstore.

## Usage

This library is primarily intended to be used a dependency for Go applications that need support for verifying Sigstore bundles, but it does include a small verifier CLI that can be used for testing.

### Library

To use as a library, you need to create a type that implements the signed entity interface, and then apply a policy to it.

The type `bundle.ProtobufBundle` is included and implements the signed entity interface, and can be used to load Sigstore Bundles from JSON.

The standard Sigstore policy is composed of all the checks that are used to verify a Sigstore Bundle signed by Sigstore public infrastructure. It is wrapped in a helper function called `VerifyKeyless`.

This example includes the standard flow of loading a Sigstore Bundle from its JSON representation (stored in a byte slice), and verifying it with the standard Sigstore policy:

```go
	var b bundle.ProtobufBundle
	err = b.UnmarshalJSON(bundleBytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = policy.VerifyKeyless(&b)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
```

### CLI

To use the example CLI, invoke with `go run` like so:

```shell
go run ./cmd/sigstore-verifier examples/provenance.json
```

Alternatively, you can install a binary of the CLI like so:

```shell
go install ./cmd/sigstore-verifier
sigstore-verifier examples/provenance.json
```

## Testing

Tests are invoked using the standard Go testing framework. A helper exists in the Makefile also.

```shell
    make test
```

## Example bundles

### examples/provenance.json

This came from https://www.npmjs.com/package/sigstore/v/1.3.0/provenance, with the outermost "bundle" key stripped off.
