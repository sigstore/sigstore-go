# Signing using `sigstore-go`

This document will walk you through using `sigstore-go` to generate a Sigstore bundle.

## Requirements

- Unix-compatible OS
- [Go 1.21](https://go.dev/doc/install)

## Installation

Clone this repository and run the following command:

```shell
$ make build-examples
$ go install ./examples/sigstore-go-signing
```

## Bundle

This library generates [Sigstore bundles](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) encoded as JSON, which are composed of raw message signatures or attestations, combined with certificates, transparency log data, signed timestamps, and other metadata to form a single, verifiable artifact.

## Trusted Root

You can optionally provide a [trusted root](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto), containing root/intermediate certificate of the Fulcio/TSA/Rekor instances used to sign the bundle, which the signer will use to verify the bundle before returning it. Because the trusted root content changes as key material is rotated, the example uses TUF to fetch an up-to-date trusted root.

## Abstractions

The library provides enough implementation to sign content with the Sigstore public good instance. It also provides interfaces so that in can be used in a wide variety of private deployments or other use-cases:

- `Content` to represent what it is you want to be signed. Implementations are provided for `PlainData` or `DSSE` encoded content.
- `Keypair` for how the content should be signed. A default implementation of `EphemeralKeypair` is provided, intended to be used with Sigstore Fulcio, with a ECDSA key using the P-256 curve. If you need a different key type, or a durable key, or support for a KMS, you can implement the `Keypair` interface.
- `CertificateProvider` for obtaining a code signing certificate. A default `Fulcio` implementation is provided.
- `Transparency` for obtaining a transparency log entry. A default `Rekor` implementation is provided.

Although not an interface, there is also a `TimestampAuthority` that you can use to corroborate when the signing certificate was obtained.

## Interface

Looking at the `Bundle()` function and its associated `BundleOptions`, you can see what is required to generate a bundle with signed content:

- `Content` that represents what it is you want to be signed
- `Keypair` for what to use to sign the content

And then optionally:

- A `CertificateProvider`
- One or more `TimestampAuthorities`
- One or more `Transparency` log entry providers
- `TrustedRoot` material to verify the bundle before returning it

See [sigstore-go-signing](../examples/sigstore-go-signing/main.go) for an example of how to use this interface.

## Examples

A very basic example of signing with a provided keypair with a signed timestamp:

```bash
$ sigstore-go-signing -tsa examples/sigstore-go-signing/hello_world.txt
Using public key:

-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY51jsbL5o8ge+FAcxpYjQeDEe1n5
WK+8DzwCkLLPJHISIvsiS93PTVDPpmbAASOl2Y4ZHqRsxb3aPMaQmN4sew==
-----END PUBLIC KEY-----


{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial":{"publicKey":{"hint":"WpMWlwBZxXlzAjt/fxK4Nd9VYm7PH3cnr3TTVmdQ5SQ="}, "timestampVerificationData":{"rfc3161Timestamps":[{"signedTimestamp":"MIIC0jADAgEAMIICyQYJKoZIhvcNAQcCoIICujCCArYCAQMxDTALBglghkgBZQMEAgIwgbwGCyqGSIb3DQEJEAEEoIGsBIGpMIGmAgEBBgkrBgEEAYO/MAIwMTANBglghkgBZQMEAgEFAAQgkaG6xajtAtsOoLy40vPZp+nDZRIWKnES2RqHDU7rmf4CFQC3ipDzPRUatDNLHxecg+XOCLSvWRgPMjAyNDA2MDcxNDExNTNaMAMCAQGgNqQ0MDIxFTATBgNVBAoTDEdpdEh1YiwgSW5jLjEZMBcGA1UEAxMQVFNBIFRpbWVzdGFtcGluZ6AAMYIB3zCCAdsCAQEwSjAyMRUwEwYDVQQKEwxHaXRIdWIsIEluYy4xGTAXBgNVBAMTEFRTQSBpbnRlcm1lZGlhdGUCFDz4J+p3q9T1P++QkPutn3Qbms2gMAsGCWCGSAFlAwQCAqCCAQUwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNDA2MDcxNDExNTNaMD8GCSqGSIb3DQEJBDEyBDCBYMVKhy7Mh+uUo0ycmn+Cl4swv4Z2t0TVuI+v0iNFJ4KTxB94bEALa2aaJZhNURswgYcGCyqGSIb3DQEJEAIvMXgwdjB0MHIEIHlI8iapfsPTNvwCoQbp1RaqmufUNHq7MbJ0CRlZCRsHME4wNqQ0MDIxFTATBgNVBAoTDEdpdEh1YiwgSW5jLjEZMBcGA1UEAxMQVFNBIGludGVybWVkaWF0ZQIUPPgn6ner1PU/75CQ+62fdBuazaAwCgYIKoZIzj0EAwMEaDBmAjEA3LlfE26IGKXCWgfGOxohAcz7/IlnRntEOI0lmknn5TgPa+VWfs1SqUBOKrYXPZutAjEAoNgsnlcSraDhAqdnv0llxvQLVEvZDBny1I1UgrtsAEnks9LWtH67bdwYrHRsCBAW"}]}}, "messageSignature":{"messageDigest":{"algorithm":"SHA2_256", "digest":"uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="}, "signature":"MEUCIQDlK0ZyYsGeh1NC7MiAL+mT54jdQakhelpy5Vz5MmWEbgIgRn51DlDW6rgIY7KMUq+7sC8BjZYzh4QtmcPjJiF4RSA="}}
```
