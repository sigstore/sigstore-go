# PyPI (PEP 740) attestation verification using `sigstore-go`

This document walks through using `sigstore-go` to verify the attestations PyPI publishes for a package distribution.

## Disclaimer

This is an example of how to use the `sigstore-go` library to verify PyPI attestations and is not intended to replace [`pypi-attestations`](https://github.com/pypi/pypi-attestations) and/or be reused in production.

## Overview

PyPI accepts and redistributes Sigstore-based attestations for uploaded distributions, as specified by [PEP 740](https://peps.python.org/pep-0740/). For each attested file, the [Integrity API](https://docs.pypi.org/api/integrity/) serves a *provenance object* containing one or more attestations from the publishing identity (typically a GitHub Actions workflow via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)).

A PEP 740 attestation carries the same verification material as a [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) — a signing certificate, transparency log entries, and a DSSE envelope — but re-arranged: the certificate is base64 DER rather than a certificate chain, the transparency log entries are protojson-serialized `TransparencyLogEntry` messages, and the envelope is split into its statement and signature fields rather than a single DSSE object. Verifying one with `sigstore-go` means reconstructing a bundle from this shape first.

## Fetching a release's provenance

The examples below assume an `*http.Client` named `httpClient`, a PEP 503-normalized `project` name, a release `version`, and the distribution `filename` being checked.

PyPI's [Simple API](https://peps.python.org/pep-0691/) lists a project's files along with the sha256 digest each attestation must ultimately be bound to:

```go
type simpleFile struct {
	Filename string            `json:"filename"`
	Hashes   map[string]string `json:"hashes"`
}

type simpleProject struct {
	Files []simpleFile `json:"files"`
}
```

```go
req, err := http.NewRequest(http.MethodGet, indexURL+"/simple/"+project+"/", nil)
if err != nil {
	return err
}
req.Header.Set("Accept", "application/vnd.pypi.simple.v1+json")
resp, err := httpClient.Do(req)
if err != nil {
	return fmt.Errorf("fetching project metadata: %w", err)
}
defer resp.Body.Close()
// ...decode resp.Body into a simpleProject
```

For a given file, its provenance object is served by the Integrity API at `/integrity/{project}/{version}/{filename}/provenance`:

```go
req, err := http.NewRequest(http.MethodGet, indexURL+"/integrity/"+project+"/"+version+"/"+filename+"/provenance", nil)
if err != nil {
	return err
}
req.Header.Set("Accept", "application/vnd.pypi.integrity.v1+json")
resp, err := httpClient.Do(req)
if err != nil {
	return fmt.Errorf("fetching provenance: %w", err)
}
defer resp.Body.Close()
// ...decode resp.Body into a provenance
```

The provenance object is one or more attestation bundles, each carrying attestations from one Trusted Publisher identity:

```go
// attestation is the PEP 740 attestation object. encoding/json decodes the
// base64 string fields typed as []byte automatically.
type attestation struct {
	Version              int `json:"version"`
	VerificationMaterial struct {
		Certificate         []byte            `json:"certificate"`
		TransparencyEntries []json.RawMessage `json:"transparency_entries"`
	} `json:"verification_material"`
	Envelope struct {
		Statement []byte `json:"statement"`
		Signature []byte `json:"signature"`
	} `json:"envelope"`
}

type provenance struct {
	AttestationBundles []struct {
		Attestations []attestation `json:"attestations"`
	} `json:"attestation_bundles"`
}
```

## Reconstructing a Sigstore bundle

Converting one PEP 740 attestation into a bundle `sigstore-go` can verify is a purely structural transform: the certificate is wrapped as-is, the transparency entries are unmarshaled with `protojson` (they're already `TransparencyLogEntry` messages, just JSON-encoded), and the envelope's statement/signature pair becomes a `dsse.Envelope`.

```go
import (
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// toBundle reconstructs a Sigstore bundle from a PEP 740 attestation. The
// attestation carries the same material as a bundle — signing certificate,
// transparency log entries, and DSSE envelope — just re-arranged, so the
// conversion is purely structural.
func toBundle(a attestation) (*bundle.Bundle, error) {
	entries := make([]*protorekor.TransparencyLogEntry, 0, len(a.VerificationMaterial.TransparencyEntries))
	for _, raw := range a.VerificationMaterial.TransparencyEntries {
		// PEP 740 stores transparency entries as protojson-serialized
		// TransparencyLogEntry messages.
		var e protorekor.TransparencyLogEntry
		if err := protojson.Unmarshal(raw, &e); err != nil {
			return nil, fmt.Errorf("decoding transparency entry: %w", err)
		}
		entries = append(entries, &e)
	}

	pb := &protobundle.Bundle{
		// v0.3 is the first bundle media type that carries a bare signing
		// certificate rather than a certificate chain.
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: a.VerificationMaterial.Certificate},
			},
			TlogEntries: entries,
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     a.Envelope.Statement,
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []*protodsse.Signature{{Sig: a.Envelope.Signature}},
			},
		},
	}
	return bundle.NewBundle(pb)
}
```

## Verifying against the expected publisher and artifact digest

At least one attestation in the provenance object must verify against the expected identity, and — critically — against the exact sha256 digest of the file being checked. Without binding the artifact digest, an attestation for one file in a release would also "verify" for a different file in the same release:

```go
// verifyProvenance requires at least one attestation in the provenance
// object to verify against the identity policy and the file's digest.
func verifyProvenance(verifier *verify.Verifier, certID verify.CertificateIdentity, prov *provenance, digest []byte) error {
	// The artifact policy binds the DSSE statement's subject digest to the
	// sha256 of the exact file being verified — without it, an attestation
	// for a different file in the same release would still verify.
	policy := verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(certID))

	var lastErr error
	count := 0
	for _, ab := range prov.AttestationBundles {
		for _, a := range ab.Attestations {
			count++
			b, err := toBundle(a)
			if err != nil {
				lastErr = err
				continue
			}
			res, err := verifier.Verify(b, policy)
			if err != nil {
				lastErr = err
				continue
			}
			if res.Signature != nil && res.Signature.Certificate != nil {
				fmt.Printf("  identity: %s (issuer %s)\n",
					res.Signature.Certificate.SubjectAlternativeName,
					res.Signature.Certificate.Issuer)
			}
			return nil
		}
	}
	if count == 0 {
		return fmt.Errorf("provenance object contains no attestations")
	}
	return fmt.Errorf("no attestation verified: %w", lastErr)
}
```

`verifier` here is an ordinary `sigstore-go` verifier over the public-good trusted root, the same as in the [verification walkthrough](verification.md):

```go
client, err := tuf.New(tuf.DefaultOptions())
trustedRootJSON, err := client.GetTarget("trusted_root.json")
trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
verifier, err := verify.NewVerifier(trustedRoot, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
```

And `certID` names the Trusted Publisher identity the certificate's SAN and OIDC issuer must match:

```go
certID, err := verify.NewShortCertificateIdentity(
	"https://token.actions.githubusercontent.com", "",
	"", `^https://github.com/sigstore/sigstore-python/\.github/workflows/release\.yml@.*$`,
)
```

## Example

Running the above against the [`sigstore`](https://pypi.org/project/sigstore/) package (sigstore-python), which publishes attestations from its GitHub Actions release workflow, verifies both of its 4.3.0 distribution files:

```text
  identity: https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.3.0 (issuer https://token.actions.githubusercontent.com)
Verified sigstore-4.3.0-py3-none-any.whl (sha256:0f60c46c92fd4e871fbec979c9ae2aa381d7a93fbb774e49c9964550e5e16856)
  identity: https://github.com/sigstore/sigstore-python/.github/workflows/release.yml@refs/tags/v4.3.0 (issuer https://token.actions.githubusercontent.com)
Verified sigstore-4.3.0.tar.gz (sha256:3c4b566bddfcc53e73d3adc06acf4311d72be0d907a167133abdc815a472a59b)
```

Verification fails when the attestation was produced by a different identity than expected:

```text
error: sigstore-4.3.0-py3-none-any.whl: no attestation verified: failed to verify certificate identity: no matching CertificateIdentity found, ...
```

## What is verified

For each distribution file, at least one attestation must pass all of:

1. **Signature** — the DSSE envelope's signature over the in-toto statement, using the key bound in the signing certificate.
2. **Transparency log** — inclusion of the signing event in Rekor, with the integrated time inside the certificate's validity window.
3. **Certificate identity** — the certificate's SAN and OIDC issuer match the expected publisher identity.
4. **Artifact binding** — the statement's subject digest equals the sha256 the index reports for the file, so an attestation for one file cannot vouch for another.

PyPI itself only redistributes attestations it has verified on upload, but a downstream consumer should not take the index's word for it — this walkthrough performs the full verification locally.
