# ML-DSA Transparent Signatures Verification Example

This example demonstrates how to use the `IdentityVerifier` API in `pkg/verify` to verify a v2.0 Bundle containing an ML-DSA Transparent Signature against the Sigstore PQC staging `TrustedRoot` (or a local `trusted_root.json`).

## Overview

The example performs the following steps:
1. Loads the v2.0 signature bundle and the signed artifact.
2. Fetches the `TrustedRoot` from the Sigstore PQC staging TUF repository (`https://tuf.v2.sigstage.dev`) by default, or loads one via `--trusted-root`.
3. Configures the verification policy with expected OIDC issuer/identity or a trusted ML-DSA-44 public key.
4. Verifies the transparency log checkpoint, inclusion proof, and either the public key signature or OIDC identity claims.

## Prerequisites

Generate a valid v2.0 bundle using `examples/sigstore-go-transparent-signing` first (producing `bundle.json` and, for key-based signing, `pubkey.pem`).

## Running the Example

For verifying with an OIDC identity:

```bash
go run ./examples/sigstore-go-transparent-verification --expected-issuer=<issuer> --expected-identity=<identity> bundle.json artifact
```

For verifying with a public key:

```bash
go run ./examples/sigstore-go-transparent-verification --pub-key=pubkey.pem bundle.json artifact
```

Pass `--trusted-root=/path/to/trusted_root.json` to verify against a custom or local deployment instead of PQC staging.

If successful, the tool outputs:
```text
Transparent signature verified successfully!
```
