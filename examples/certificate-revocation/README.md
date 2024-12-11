# Basic CRL (Certificate Revocation List) example

This example demonstrates how to use a custom TrustedMaterial that implements a Certificate Revocation List (CRL) to revoke certificates.

This custom TrustedMaterial type wraps any other TrustedMaterial (such as that provided by the Public Good Instance) and acts as a middleware that checks the CRL before the leaf certificate is verified by the wrapped TrustedMaterial.

The code is implemented in `NewBasicCRLTrustedMaterial`, in `crl.go`. The unit test in `crl_test.go` demonstrates how it can be used.
