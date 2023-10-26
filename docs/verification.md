# Verification using `sigstore-go`

This document will walk through using `sigstore-go` to verify a Sigstore Bundle.

## Requirements

- Unix-compatible OS
- [Go 1.21](https://go.dev/doc/install)

## Installation

Clone this repository and use `make install` to install the `sigstore-go` CLI:

```shell
$ make install
go install ./cmd/...
```

## Bundle

This library supports verifying [Sigstore bundles](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) encoded as JSON, which are composed of raw message signatures or attestations, combined with certificates, transparency log data, signed timestamps, and other metadata to form a single, verifiable artifact.

Signing is not currently supported by this library, but you may use [`sigstore-js`](https://github.com/sigstore/sigstore-js) or [`sigstore-python`](https://github.com/sigstore/sigstore-python) to generate/sign a bundle and verify it with this library.

An example Sigstore bundle is included in this distribution at [`examples/bundle-provenance.json`](../examples/bundle-provenance.json). 

## Trusted Root

The verifier allows you to use the Sigstore Public Good TUF root or your own custom [trusted root](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto) containing the root/intermediate certificates of the Fulcio/TSA/Rekor instances used to sign the bundle, in order to verify common open source bundles or bundles signed by your own private Sigstore instance.

## Abstractions

This library includes a few abstractions to support different use cases, testing, and extensibility:

- `SignedEntity` - an interface type respresenting a signed message or attestation, with a signature and metadata, implemented by `ProtobufBundle`, a type which wraps the `Bundle` type from `protobuf-specs`.
- `TrustedMaterial` - an interface type representing a trusted set of keys or certificates for verifying certificates, timestamps, and artifact transparency logs, implemented by `TrustedRoot`

## Verifier

The main entrypoint for verification is called `SignedEntityVerifier`, which takes a `TrustedMaterial` and a set of `VerifierOption`s to configure the verification process. A `SignedEntityVerifier` has a single method, `Verify`, which accepts a `SignedEntity` (generally, a Sigstore bundle) and a `Policy` and returns a `VerificationResult`.

As you can see, there are two places you can provide configuration for the verifier:

- `NewSignedEntityVerifier` - "global options", such as the trusted material, and options for verifying the bundle's signatures, such as thresholds and whether to perform online verification, whether to check for SCTs, etc.
- `Verify` - the bundle to be verified, and options for verifying the bundle's contents, such as asserting a specific subject digest or certificate issuer or SAN

This is compatible with batch workflows where a single verifier is used to verify many bundles, and the bundles themselves may be verified against different identities/artifacts.

## Go API

To verify a bundle with the Go API, you'll need to:

- establish a trusted root
- create a verifier using the required options
- set up a policy containing the expected identity and digest to verify
- verify the bundle

Going through this step-by-step, we'll start by loading the trusted root from the Sigstore TUF repo:

```go
	trustedrootJSON, err := tuf.GetTrustedrootJSON("tuf-repo-cdn.sigstore.dev", "tufcache")
	if err != nil {
		panic(err)
	}

	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedrootJSON)
	if err != nil {
		panic(err)
	}
```

Next, we'll create a verifier with some options, which will enable SCT verification, ensure a single transparency log entry, and perform online verification:

```go
	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithOnlineVerification())
	if err != nil {
		panic(err)
	}
```

Then, we need to prepare the expected artifact digest and certificate identity. Note that these options may be omitted, but only if the options `WithoutIdentitiesUnsafe`/`WithoutArtifactUnsafe` are provided. This is a failsafe to ensure that the caller is aware that simply verifying the bundle is not enough, you must also verify the contents of the bundle against a specific identity and artifact.

```go
	digest, err := hex.DecodeString("76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751")
	if err != nil {
		panic(err)
	}

	certID, err := verify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "", "", "^https://github.com/sigstore/sigstore-js/")
	if err != nil {
		panic(err)
	}
```

Then, we load the bundle and perform the verification:

```go
	b, err := bundle.LoadJSONFromPath("./examples/bundle-provenance.json")
	if err != nil {
		panic(err)
	}

	result, err := sev.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha512", digest), verify.WithCertificateIdentity(certID)))
	if err != nil {
		panic(err)
	}
```

If the value of `err` is nil, the verification is successful and the `result` will contain details about the verification result.

Below is an example of a successful verification result, serialized as JSON:

```json
{
   "mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
   "statement": {
      "_type": "https://in-toto.io/Statement/v0.1",
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "subject": [
         {
            "name": "pkg:npm/sigstore@1.3.0",
            "digest": {
               "sha512": "76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751"
            }
         }
      ],
      "predicate": "omitted for brevity"
   },
   "signature": {
      "certificate": {
         "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
         "subjectAlternativeName": {
            "type": "URI",
            "value": "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
         },
         "issuer": "https://token.actions.githubusercontent.com",
         "githubWorkflowTrigger": "push",
         "githubWorkflowSHA": "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1",
         "githubWorkflowName": "Release",
         "githubWorkflowRepository": "sigstore/sigstore-js",
         "githubWorkflowRef": "refs/heads/main",
         "buildSignerURI": "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
         "buildSignerDigest": "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1",
         "runnerEnvironment": "github-hosted",
         "sourceRepositoryURI": "https://github.com/sigstore/sigstore-js",
         "sourceRepositoryDigest": "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1",
         "sourceRepositoryRef": "refs/heads/main",
         "sourceRepositoryIdentifier": "495574555",
         "sourceRepositoryOwnerURI": "https://github.com/sigstore",
         "sourceRepositoryOwnerIdentifier": "71096353",
         "buildConfigURI": "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
         "buildConfigDigest": "dae8bd8eb433a4147b4655c00fe73e0f22bc0fb1",
         "buildTrigger": "push",
         "runInvocationURI": "https://github.com/sigstore/sigstore-js/actions/runs/4735384265/attempts/1"
      }
   },
   "verifiedTimestamps": [
      {
         "type": "Tlog",
         "uri": "TODO",
         "timestamp": "2023-04-18T13:45:12-04:00"
      }
   ],
   "verifiedIdentity": {
      "subjectAlternativeName": {
         "regexp": "^https://github.com/sigstore/sigstore-js/"
      },
      "issuer": "https://token.actions.githubusercontent.com"
   }
}
```

Putting it together, the following script will verify the example bundle and print the result. This can be run against the example bundle in this repository, if you paste it into `main.go` and use `go run main.go` to run it.

```go
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func main() {
	trustedrootJSON, err := tuf.GetTrustedrootJSON("tuf-repo-cdn.sigstore.dev", "tufcache")
	if err != nil {
		panic(err)
	}

	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedrootJSON)
	if err != nil {
		panic(err)
	}

	sev, err := verify.NewSignedEntityVerifier(trustedMaterial, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithOnlineVerification())
	if err != nil {
		panic(err)
	}

	digest, err := hex.DecodeString("76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751")
	if err != nil {
		panic(err)
	}

	certID, err := verify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "", "", "^https://github.com/sigstore/sigstore-js/")
	if err != nil {
		panic(err)
	}

	b, err := bundle.LoadJSONFromPath("./examples/bundle-provenance.json")
	if err != nil {
		panic(err)
	}

	result, err := sev.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha512", digest), verify.WithCertificateIdentity(certID)))
	if err != nil {
		panic(err)
	}

	marshaled, err := json.MarshalIndent(result, "", "   ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(marshaled))
}
```

To explore a more advanced/configurable verification process, see the CLI implementation in [`cmd/sigstore-go/main.go`](../cmd/sigstore-go/main.go).
