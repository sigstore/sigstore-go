# ML-DSA Transparent Signatures Example

This example demonstrates how to use the `IdentityBundle` API in `pkg/sign` to sign an artifact using the ML-DSA Transparent Signatures flow. It produces a V2 Bundle containing the signature and the identity transparency log proof.

## Overview

The example performs the following steps:
1. Generates an ephemeral signing keypair, or uses a provided identity token.
2. Signs the artifact and requests an identity transparency log entry.
3. Outputs the resulting Sigstore bundle containing the signature and log proof.
4. Saves the public key to a file for later verification.

## Prerequisites

You will need an Identity Rekor service running to accept the transparency log entry. By default, the example connects to `http://localhost:3006`.
This also assumes a fake OIDC server running on `localhost:8080`.

## Running the Example

1. Create a sample file to sign:
   ```bash
   head -c 128 < /dev/urandom > artifact
   ```

2. Run the example (saving the bundle to a file):
   ```bash
   go run examples/sigstore-go-transparent-signing/main.go --rekor-addr http://localhost:3006 artifact > bundle.json
   ```
   *You can also use `--identity-token <token>` to use an OIDC token instead of a public key.*

   ```bash
   curl localhost:8080/token > token
   go run examples/sigstore-go-transparent-signing/main.go --rekor-addr http://localhost:3006 --identity-token $(cat token) artifact > bundle.json
   ```

3. The output will be a Sigstore V2 Bundle saved to `bundle.json`. Additionally, `pubkey.pub` will be created containing the ephemeral ML-DSA public key when signing with a keypair.

4. To verify the signature and the log proof, use the transparent verification example:
   ```bash
   go run examples/sigstore-go-transparent-verification/main.go --log-key=/path/to/mldsa-pub-key.pem --pub-key=pubkey.pub bundle.json artifact
   ```
