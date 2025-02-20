# Building examples

To build example programs, run `make build-examples` in the repo root.
The built executables will be in the `examples/` subdirectory:
```shell
$ make build-examples
go build -C ./examples/oci-image-verification -o oci-image-verification .
go build -C ./examples/sigstore-go-signing -o sigstore-go-signing .
go build -C ./examples/sigstore-go-verification -o sigstore-go-verification .

$ find examples -type f -perm -u+x | sort
examples/oci-image-verification/oci-image-verification
examples/sigstore-go-signing/sigstore-go-signing
examples/sigstore-go-verification/sigstore-go-verification
```

# oci-image-verification

This is a CLI for verifying signatures on the OCI images. View the help text with `-h` or `--help` for all the options.
```shell
$ ./oci-image-verification -h
Usage of ./oci-image-verification:
  -artifact string
        Path to artifact to verify
  -artifact-digest string
        Hex-encoded digest of artifact to verify
  -artifact-digest-algorithm string
        Digest algorithm (default "sha256")
  -expectedIssuer string
        The expected OIDC issuer for the signing certificate
  -expectedIssuerRegex string
        The expected OIDC issuer for the signing certificate
  -expectedSAN string
        The expected identity in the signing certificate's SAN extension
  -expectedSANRegex string
        The expected identity in the signing certificate's SAN extension
  -ignore-sct
        Ignore SCT verification - do not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
  -minBundleVersion string
        Minimum acceptable bundle version (e.g. '0.1')
  -ociImage string
        OCI image to verify
  -publicKey string
        Path to trusted public key
  -requireTimestamp
        Require either an RFC3161 signed timestamp or log entry integrated timestamp (default true)
  -requireTlog
        Require Artifact Transparency log entry (Rekor) (default true)
  -trustedrootJSONpath string
        Path to trustedroot JSON file (default "examples/trusted-root-public-good.json")
  -tufDirectory string
        Directory to store TUF metadata (default "tufdata")
  -tufRootURL string
        URL of TUF root containing trusted root JSON file
```

# sigstore-go-signing
This is a test CLI for signing sigstore bundles.
```shell
$ ./sigstore-go-signing -h
Usage of ./sigstore-go-signing:
  -id-token string
    OIDC token to send to Fulcio
  -in-toto
    Content to sign is in-toto document
  -rekor
    Including transparency log entry from Rekor
  -tsa
    Include signed timestamp from timestamp authority
```

# sigstore-go-verification

This is a CLI for verifying Sigstore bundles. View the help text with `-h` or `--help` for all the options.

```shell
$ ./sigstore-go-verification \
  -artifact-digest 76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751 \
  -artifact-digest-algorithm sha512 \
  -expectedIssuer https://token.actions.githubusercontent.com \
  -expectedSAN https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main \
  ../bundle-provenance.json
Verification successful!
{
   "version": 20230823,
   "statement": {
      "_type": "https://in-toto.io/Statement/v0.1",
      "predicateType": "https://slsa.dev/provenance/v0.2",
      "subject": ...
    },
    ...
}
```

You can also specify a TUF root with something like `-tufRootURL tuf-repo-cdn.sigstore.dev`.
