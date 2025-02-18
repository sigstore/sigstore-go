# Building examples

To build example programs, run `make build-examples` in the repo root.
The built executables will be in the `examples/` subdirectory:
```shell
$ make build-examples && ls -tr examples | tail -3
go build -C ./examples/oci-image-verification -o oci-image-verification .
go build -C ./examples/sigstore-go-signing -o sigstore-go-signing .
go build -C ./examples/sigstore-go-verification -o sigstore-go-verification .

$ find examples -type f -perm -u+x | sort
examples/oci-image-verification/oci-image-verification
examples/sigstore-go-signing/sigstore-go-signing
examples/sigstore-go-verification/sigstore-go-verification
```

# oci-image-verification

This is a CLI fo verifying signatures on the OCI images. View the help text with `-h` or `--help` for all the options.
(The usage example below is not intended to represent the best practices - add all the restrictions and verification parameters
such as `-expectedIssuer` and `-expectedSAN` applicable to your environment.)
```shell
./oci-image-verification \
  -requireTlog=false -ignore-sct -expectedIssuerRegex='.*' -expectedSANRegex='.*' \
  -trustedrootJSONpath=$HOME/dev/files/trustedroot.json -ociImage docker.company.com:4443/repo/image/name
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

