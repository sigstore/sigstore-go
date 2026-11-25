# ML-DSA Transparent Signatures Verification Example

This example demonstrates how to use the `IdentityVerifier` API in `pkg/verify` to verify a V2 Bundle containing an ML-DSA Transparent Signature.

## Overview

The example performs the following steps:
1. Loads the signature bundle and the signed artifact.
2. Configures the verification policy with expected identities or public key.
3. Verifies the artifact's signature or identity claims against the bundle.
4. Verifies the transparency log inclusion proof to ensure the signing event was logged.

## Prerequisites

You must first generate a valid V2 bundle using the transparent signing example. This process will create a `bundle.json` and (for key-based signing) a `pubkey.pub`.

## Running the Example

Follow the instructions in `examples/sigstore-go-transparent-signing/README.md` to generate a bundle first. Then you can run this example.

For verifying with an identity token:

```bash
go run examples/sigstore-go-transparent-verification/main.go --log-key=/path/to/mldsa-pub-key.pem --expected-identity=foo@bar.com --expected-issuer=http://fakeoidc:8080 bundle.json artifact
```

For verifying with a public key:

```bash
go run examples/sigstore-go-transparent-verification/main.go --log-key=/path/to/mldsa-pub-key.pem --pub-key=pubkey.pub bundle.json artifact
```

If successful, the tool will output:
```text
Transparent signature verified successfully!
```
