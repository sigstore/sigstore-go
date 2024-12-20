# Custom Certificate Validation example

This example demonstrates how to use a custom TrustedMaterial that implements a custom certificate validator.

This can be used by organizations running private PKI infrastructure to validate certificates issued by that infrastructure, or to implement a custom certificate revocation list (CRL).

This custom TrustedMaterial type wraps any other TrustedMaterial (such as that provided by the Public Good Instance) and acts as a middleware that checks the CRL before the leaf certificate is verified by the wrapped TrustedMaterial.

The code is implemented in `NewValidatingTrustedMaterial`, in `certificate_validator.go`. The unit test in `certificate_validator_test.go` demonstrates how it can be used.
