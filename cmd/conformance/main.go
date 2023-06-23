package main

import (
	"fmt"
	"log"
	"os"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/policy"
	"github.com/github/sigstore-verifier/pkg/root"
)

var bundlePath *string
var certOIDC *string
var certSAN *string

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("\t%s verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL FILE\n", os.Args[0])
}

func main() {
	if len(os.Args) < 8 {
		usage()
		os.Exit(1)
	}

	if os.Args[1] == "verify-bundle" {
		for i := 2; i < len(os.Args); i += 2 {
			switch os.Args[i] {
			case "--bundle":
				bundlePath = &os.Args[i+1]
			case "--certificate-oidc-issuer":
				certOIDC = &os.Args[i+1]
			case "--certificate-identity":
				certSAN = &os.Args[i+1]
			}
		}

		// Load bundle
		b, err := bundle.LoadJSONFromPath(*bundlePath)
		if err != nil {
			log.Fatal(err)
		}

		// Configure verification options
		opts := policy.GetDefaultOptions()
		if *certOIDC != "" {
			policy.SetExpectedOIDC(opts, *certOIDC)
		}
		if *certSAN != "" {
			policy.SetExpectedSAN(opts, *certSAN)
		}

		// Load trust root
		tr, err := root.NewTrustedRootFromPath("examples/trusted-root-public-good.json")
		if err != nil {
			log.Fatal(err)
		}

		// Verify bundle
		p := policy.NewTrustedRootPolicy(tr, opts)
		err = p.VerifyPolicy(b)
		if err != nil {
			log.Fatal(err)
		}

		// Check file against bundle
		fileBytes, err := os.ReadFile(os.Args[len(os.Args)-1])
		if err != nil {
			log.Fatal(err)
		}

		content, err := b.Content()
		if err != nil {
			log.Fatal(err)
		}

		content.EnsureFileMatchesDigest(fileBytes)
	} else {
		log.Fatalf("Unsupported command %s", os.Args[1])
	}
}
