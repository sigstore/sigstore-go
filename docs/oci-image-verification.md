# OCI image verification using `sigstore-go`

This document will walk through using the `sigstore-go` CLI to verify an OCI image reference.

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

This library supports generating and verifying a [Sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) based on an OCI image reference. Signing is not currently supported by this library.

## Trusted Root

The verifier allows you to use the Sigstore Public Good TUF root or your own custom [trusted root](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto) containing the root/intermediate certificates of the Fulcio/TSA/Rekor instances used to sign the bundle, in order to verify common open source bundles or bundles signed by your own private Sigstore instance.

## Verification Process

In this example, we'll use the `sigstore-go` CLI to verify an OCI image reference. The CLI is a thin wrapper around the Go API, so the process is the same, but the CLI provides a convenient way to verify an OCI image reference without writing any code.
The image we are going to verify is `ghcr.io/stacklok/minder/server:latest`

```shell
sigstore-go --ociImage="ghcr.io/stacklok/minder/server:latest" --tufRootURL="tuf-repo-cdn.sigstore.dev" --expectedSANRegex="^https://github.com/stacklok/minder/" --expectedIssuer="https://token.actions.githubusercontent.com"
```

Upon successful verification, the CLI will print the verification result in JSON format along with a `Verification successful!` message.

Below is an example of the bundle that was generated for this image(at that point of time) followed by the successful verification result, serialized as JSON:

```json
{
   "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
   "verificationMaterial": {
      "x509CertificateChain": {
         "certificates": [
            {
               "rawBytes": "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"
            }
         ]
      },
      "tlogEntries": [
         {
            "logIndex": "53194260",
            "logId": {
               "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
            },
            "kindVersion": {
               "kind": "hashedrekord",
               "version": "0.0.1"
            },
            "integratedTime": "1701205628",
            "inclusionPromise": {
               "signedEntryTimestamp": "MEYCIQCOvYr8ezbNfJMGw0CIT4krwy2fSnIVMUfWJ4Xjn7ZsOQIhAMROYirqcbs76Y4B4I/wDlqdDavbx3OB6/YPezB46npD"
            },
            "canonicalizedBody": "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiJhOWQzZWE4Mzk3OWJmYTM1MjJkNTkwNjRjMzI0NzNlZDNiYWM4OGY2MmMzNmIzZGQyNDNmZWZlOTVkZWM2ZGEwIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJR1RkZnIwbytoQWlMTEZzTkNNR1ZoRnF2aTRYNm52V290amZwc1NPaThxakFpQmloMC9FVjhYckRnMWpiUTVyK2R5Y080Wi94a0hWbGg1VUZSWThnQ2ZzdGc9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVZDBSRU5EUW1wMVowRjNTVUpCWjBsVlltUTBaMmgwZW5RMFJrazJPVmhVVjBaSE1tcGtVbWhSWjNoamQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcE5lRTFVU1RSTmFrVjNUbnBCTkZkb1kwNU5hazE0VFZSSk5FMXFSWGhPZWtFMFYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVZaVUZkU1R6WXhOV0ZzV1hJemRUQm5VMmxwVERBMU5scDVhMUZSUWs5bE0wOVZiWGtLYjBsd1QzZE5jRmh2VUU0NGVsUnVOVlEyVDBGeFJtbHlabWN5YmpsNlUzZFJRa1EwWlZoeFJsaGxiWHBTTjBrdmIyRlBRMEpXYjNkbloxWlhUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZzYkdobUNtMDJRbTk1Y1VSTVNFMUZRbWRSY2xaWE5IQkdibFYzZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDFwQldVUldVakJTUVZGSUwwSkdiM2RYU1ZwWFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVEROT01GbFhUbkppUnpseVRESXhjQXBpYlZKc1kyazRkVm95YkRCaFNGWnBURE5rZG1OdGRHMWlSemt6WTNrNWFtRkhSbmxrUXpGM1pGZEtjMkZZVG05TWJteDBZa1ZDZVZwWFducE1NbWhzQ2xsWFVucE1NakZvWVZjMGQwOVJXVXRMZDFsQ1FrRkhSSFo2UVVKQlVWRnlZVWhTTUdOSVRUWk1lVGt3WWpKMGJHSnBOV2haTTFKd1lqSTFla3h0WkhBS1pFZG9NVmx1Vm5wYVdFcHFZakkxTUZwWE5UQk1iVTUyWWxSQlUwSm5iM0pDWjBWRlFWbFBMMDFCUlVOQ1FWSjNaRmhPYjAxRVdVZERhWE5IUVZGUlFncG5OemgzUVZGTlJVdEVXbXRaZWxwcVRtMU5lVTU2UlRST1IxazFUVlJzYVZsVVdtcFpWRWt4VDBkVmQwNXFVbWxhUkdScldrUkZORnBVYTNsTlJFRjNDa2xCV1V0TGQxbENRa0ZIUkhaNlFVSkNRVkZUVlVoV2FXSkhiSHBoUTBKSldsZDRkRWxGVG05WldFb3dUVUl3UjBOcGMwZEJVVkZDWnpjNGQwRlJWVVVLUkROT01GbFhUbkppUnpseVRESXhjR0p0VW14amFrRmtRbWR2Y2tKblJVVkJXVTh2VFVGRlIwSkJPWGxhVjFwNlRESm9iRmxYVW5wTU1qRm9ZVmMwZHdwUGQxbExTM2RaUWtKQlIwUjJla0ZDUTBGUmRFUkRkRzlrU0ZKM1kzcHZka3d6VW5aaE1sWjFURzFHYW1SSGJIWmliazExV2pKc01HRklWbWxrV0U1c0NtTnRUblppYmxKc1ltNVJkVmt5T1hSTlIxbEhRMmx6UjBGUlVVSm5OemgzUVZGclJWZEJlRmRoU0ZJd1kwaE5Oa3g1T1c1aFdGSnZaRmRKZFZreU9YUUtURE5PTUZsWFRuSmlSemx5VERJeGNHSnRVbXhqYVRoMVdqSnNNR0ZJVm1sTU0yUjJZMjEwYldKSE9UTmplVGxxWVVkR2VXUkRNWGRrVjBwellWaE9id3BNYm14MFlrVkNlVnBYV25wTU1taHNXVmRTZWt3eU1XaGhWelIzVDBGWlMwdDNXVUpDUVVkRWRucEJRa05uVVhGRVEyY3lXa2ROTWxsNldtcE5hbU40Q2s5RVVtMVBWRVUxV1cxRk1sa3lSWGxPVkdoc1RVUlpNRmx0VVROYVIxRjRUMGRWTlUxcVFYZE5RakJIUTJselIwRlJVVUpuTnpoM1FWRnpSVVIzZDA0S1dqSnNNR0ZJVm1sTVYyaDJZek5TYkZwRVFYbENaMjl5UW1kRlJVRlpUeTlOUVVWTlFrTlJUVWx0YURCa1NFSjZUMms0ZGxveWJEQmhTRlpwVEcxT2RncGlVemw2WkVkR2FtRXllSFpoZVRsMFlWYzFhMXBZU1hkUFFWbExTM2RaUWtKQlIwUjJla0ZDUkZGUmNVUkRaekphUjAweVdYcGFhazFxWTNoUFJGSnRDazlVUlRWWmJVVXlXVEpGZVU1VWFHeE5SRmt3V1cxUk0xcEhVWGhQUjFVMVRXcEJkMDFDT0VkRGFYTkhRVkZSUW1jM09IZEJVVFJGUlZGM1VHTnRWbTBLWTNrNWIxcFhSbXRqZVRsMFdWZHNkVTFDYTBkRGFYTkhRVkZSUW1jM09IZEJVVGhGUTNkM1NrNXFTVEJOUkZVeVRsUlZORTFEYzBkRGFYTkhRVkZSUWdwbk56aDNRVkpCUlVoUmQySmhTRkl3WTBoTk5reDVPVzVoV0ZKdlpGZEpkVmt5T1hSTU0wNHdXVmRPY21KSE9YSk5RbXRIUTJselIwRlJVVUpuTnpoM0NrRlNSVVZEZDNkS1RWUkZkMDFxVFROT2VsRXlUVWRaUjBOcGMwZEJVVkZDWnpjNGQwRlNTVVZYUVhoWFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVUtXVEk1ZEV3elRqQlpWMDV5WWtjNWNrd3lNWEJpYlZKc1kyazRkVm95YkRCaFNGWnBURE5rZG1OdGRHMWlSemt6WTNrNWFtRkhSbmxrUXpGM1pGZEtjd3BoV0U1dlRHNXNkR0pGUW5sYVYxcDZUREpvYkZsWFVucE1NakZvWVZjMGQwOUJXVXRMZDFsQ1FrRkhSSFo2UVVKRmQxRnhSRU5uTWxwSFRUSlplbHBxQ2sxcVkzaFBSRkp0VDFSRk5WbHRSVEpaTWtWNVRsUm9iRTFFV1RCWmJWRXpXa2RSZUU5SFZUVk5ha0YzVFVKUlIwTnBjMGRCVVZGQ1p6YzRkMEZTVVVVS1FtZDNSV05JVm5waFJFSldRbWR2Y2tKblJVVkJXVTh2VFVGRlZrSkZZMDFTVjJnd1pFaENlazlwT0haYU1td3dZVWhXYVV4dFRuWmlVemw2WkVkR2FncGhNbmgyWVhrNWRHRlhOV3RhV0VsMldWZE9NR0ZYT1hWamVUbDVaRmMxZWt4NlkzZE5hbEV4VFVSSk1FOUVRWFpaV0ZJd1dsY3hkMlJJVFhaTlZFRlhDa0puYjNKQ1owVkZRVmxQTDAxQlJWZENRV2ROUW01Q01WbHRlSEJaZWtOQ2FXZFpTMHQzV1VKQ1FVaFhaVkZKUlVGblVqaENTRzlCWlVGQ01rRk9NRGtLVFVkeVIzaDRSWGxaZUd0bFNFcHNiazUzUzJsVGJEWTBNMnA1ZEM4MFpVdGpiMEYyUzJVMlQwRkJRVUpxUW1aQ01XUjNRVUZCVVVSQlJXTjNVbEZKYUFwQlVFOVJaVGxLWWpGblNEQmpOWEV2YkhCcWVuUndlWEpPTWxBMFdtMHJlRWhGZUdaSUwyMUlWVzlQU0VGcFFtZERiSE5xV25FMFlWSk5kM1U0VGpkaUNsRndNRGRpWkdseUszTnJUVGx3VFZSMWVGRXZabUpyVFVOVVFVdENaMmR4YUd0cVQxQlJVVVJCZDA1dVFVUkNhMEZxUVRkNVVtOWpabm81ZUU1V1MwNEtXR0ZrYTB3MWNGaGpORFV6ZFdGbGNtTXZXVGRvY25SV2EwcDJTVEp0V0VaWWJEUXlRbGREWTJzemMxWlFTSEYyZG5SQlEwMUVMM1pQWWpOaVYzRkhWQW8xZVZSTVUySjBjRmg0UWs1dVkzSndNbTh3UzFJeE1tTXhZemQyTlcxb2RHWTVWV1JRYnpGRk0weEpRVmxzY1hCUGIyb3pVVkU5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19"
         }
      ]
   },
   "messageSignature": {
      "messageDigest": {
         "algorithm": "SHA2_256",
         "digest": "qdPqg5eb+jUi1ZBkwyRz7TusiPYsNrPdJD/v6V3sbaA="
      },
      "signature": "MEQCIGTdfr0o+hAiLLFsNCMGVhFqvi4X6nvWotjfpsSOi8qjAiBih0/EV8XrDg1jbQ5r+dycO4Z/xkHVlh5UFRY8gCfstg=="
   }
}
```

and the verification result:

```json
{
  "mediaType": "application/vnd.dev.sigstore.verificationresult+json;version=0.1",
  "signature": {
    "certificate": {
      "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev",
      "subjectAlternativeName": {
        "type": "URI",
        "value": "https://github.com/stacklok/minder/.github/workflows/chart-publish.yml@refs/heads/main"
      },
      "issuer": "https://token.actions.githubusercontent.com",
      "githubWorkflowTrigger": "push",
      "githubWorkflowSHA": "6dc6c6c27184f919ba6ca258e064bd7dd18e9200",
      "githubWorkflowName": "Publish Helm Chart",
      "githubWorkflowRepository": "stacklok/minder",
      "githubWorkflowRef": "refs/heads/main",
      "buildSignerURI": "https://github.com/stacklok/minder/.github/workflows/chart-publish.yml@refs/heads/main",
      "buildSignerDigest": "6dc6c6c27184f919ba6ca258e064bd7dd18e9200",
      "runnerEnvironment": "github-hosted",
      "sourceRepositoryURI": "https://github.com/stacklok/minder",
      "sourceRepositoryDigest": "6dc6c6c27184f919ba6ca258e064bd7dd18e9200",
      "sourceRepositoryRef": "refs/heads/main",
      "sourceRepositoryIdentifier": "624056558",
      "sourceRepositoryOwnerURI": "https://github.com/stacklok",
      "sourceRepositoryOwnerIdentifier": "110237746",
      "buildConfigURI": "https://github.com/stacklok/minder/.github/workflows/chart-publish.yml@refs/heads/main",
      "buildConfigDigest": "6dc6c6c27184f919ba6ca258e064bd7dd18e9200",
      "buildTrigger": "push",
      "runInvocationURI": "https://github.com/stacklok/minder/actions/runs/7024502480/attempts/1",
      "sourceRepositoryVisibilityAtSigning": "public"
    }
  },
  "verifiedTimestamps": [
    {
      "type": "Tlog",
      "uri": "TODO",
      "timestamp": "2023-11-28T23:07:08+02:00"
    }
  ],
  "verifiedIdentity": {
    "subjectAlternativeName": {
      "regexp": "^https://github.com/stacklok/minder/"
    },
    "issuer": "https://token.actions.githubusercontent.com"
  }
}
```

To explore a more advanced/configurable verification process, see the CLI implementation in [`cmd/sigstore-go/main.go`](../cmd/sigstore-go/main.go).
