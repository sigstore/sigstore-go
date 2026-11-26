# ML-DSA Transparent Signatures Example

This example demonstrates how to use the `IdentityBundle` API in `pkg/sign` to sign an artifact using the ML-DSA Transparent Signatures flow against the Sigstore PQC staging instance (or a custom `SigningConfig`/`TrustedRoot`). It produces a v2.0 Bundle containing the identity transparency log proof (and signature when signing with a keypair).

## Overview

The example performs the following steps:
1. Fetches the `SigningConfig` and `TrustedRoot` from the Sigstore PQC staging TUF repository (`https://tuf.v2.sigstage.dev`) by default, or loads them from local files.
2. Selects an identity transparency log (`majorApiVersion: 3`) from the `SigningConfig`.
3. Runs an interactive browser-based OIDC login against the `SigningConfig`'s OIDC provider by default, or generates an ephemeral ML-DSA-44 signing keypair when `--pub-key-out` is specified.
4. Submits the artifact digest and credential to the identity transparency log and self-verifies the resulting bundle against the `TrustedRoot`.
5. Writes the resulting Sigstore v2.0 bundle to `bundle.json` (configurable via `-o`/`--out`, or `-` for stdout), and prints the logged OIDC `issuer` and `identity` (or writes the PEM-encoded public key when `--pub-key-out` is set).

## Running the Example

1. Create a sample file to sign:
   ```bash
   head -c 128 < /dev/urandom > artifact
   ```

2. Sign interactively with OIDC (opens a browser to authenticate, prints the logged issuer/identity, and writes `bundle.json`):
   ```bash
   go run ./examples/sigstore-go-transparent-signing -o bundle.json artifact
   ```

   Or sign with a generated ML-DSA-44 keypair instead of OIDC (writing the PEM public key to `pubkey.pem`):
   ```bash
   go run ./examples/sigstore-go-transparent-signing --pub-key-out=pubkey.pem -o bundle.json artifact
   ```

   You can also point to a custom or local deployment with `--signing-config` and `--trusted-root`.

3. Verify the resulting bundle with the transparent verification example:
   ```bash
   # For OIDC signing:
   go run ./examples/sigstore-go-transparent-verification --expected-issuer=<issuer> --expected-identity=<identity> bundle.json artifact

   # For keypair signing:
   go run ./examples/sigstore-go-transparent-verification --pub-key=pubkey.pem bundle.json artifact
   ```
