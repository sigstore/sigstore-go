# sigstore-go-verification

This is a CLI for verifying Sigstore bundles. View the help text with `-h` or `--help` for all the options.

```shell
$ go run . \
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

