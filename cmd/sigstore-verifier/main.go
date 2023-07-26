package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tuf"
	"github.com/github/sigstore-verifier/pkg/verifier"
	"github.com/sigstore/sigstore/pkg/signature"
)

var expectedOIDC *string
var expectedSAN *string
var requireTSA *bool
var requireTlog *bool
var minBundleVersion *string
var onlineTlog *bool
var trustedPublicKey *string
var trustedrootJSONpath *string
var tufRootURL *string
var tufDirectory *string

func init() {
	expectedOIDC = flag.String("expectedOIDC", "", "The expected OIDC issuer for the signing certificate")
	expectedSAN = flag.String("expectedSAN", "", "The expected identity in the signing certificate's SAN extension")
	requireTSA = flag.Bool("requireTSA", false, "Require RFC 3161 signed timestamp")
	requireTlog = flag.Bool("requireTlog", true, "Require Artifact Transparency log entry (Rekor)")
	minBundleVersion = flag.String("minBundleVersion", "", "Minimum acceptable bundle version (e.g. '0.1')")
	onlineTlog = flag.Bool("onlineTlog", false, "Verify Artifact Transparency log entry online (Rekor)")
	trustedPublicKey = flag.String("publicKey", "", "Path to trusted public key")
	trustedrootJSONpath = flag.String("trustedrootJSONpath", "examples/trusted-root-public-good.json", "Path to trustedroot JSON file")
	tufRootURL = flag.String("tufRootURL", "", "URL of TUF root containing trusted root JSON file")
	tufDirectory = flag.String("tufDirectory", "tufdata", "Directory to store TUF metadata")
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf("Usage: %s [OPTIONS] BUNDLE_FILE ...\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	b, err := bundle.LoadJSONFromPath(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *minBundleVersion != "" {
		if !b.MinVersion(*minBundleVersion) {
			fmt.Printf("bundle is not of minimum version %s\n", *minBundleVersion)
			os.Exit(1)
		}
	}

	opts := verifier.GetDefaultOptions()
	opts.TsaOptions.Disable = !*requireTSA
	opts.TlogOptions.Disable = !*requireTlog
	opts.TlogOptions.PerformOnlineVerification = *onlineTlog
	if *expectedOIDC != "" {
		verifier.SetExpectedOIDC(opts, *expectedOIDC)
	}
	if *expectedSAN != "" {
		verifier.SetExpectedSAN(opts, *expectedSAN)
	}

	var trustedMaterial = make(root.TrustedMaterialCollection, 0)
	var trustedrootJSON []byte

	if *tufRootURL != "" {
		trustedrootJSON, err = tuf.GetTrustedrootJSON(*tufRootURL, *tufDirectory)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else if *trustedrootJSONpath != "" {
		trustedrootJSON, err = os.ReadFile(*trustedrootJSONpath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if len(trustedrootJSON) > 0 {
		var trustedRoot *root.TrustedRoot
		trustedRoot, err = root.NewTrustedRootFromJSON(trustedrootJSON)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}
	if *trustedPublicKey != "" {
		pemBytes, err := os.ReadFile(*trustedPublicKey)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			fmt.Println("failed to decode pem block")
			os.Exit(1)
		}
		pubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial(pubKey))
	}

	if len(trustedMaterial) == 0 {
		fmt.Println("no trusted material provided")
		os.Exit(1)
	}

	p := verifier.NewVerifier(trustedMaterial, opts)
	err = p.Verify(b)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Verification successful!")
}

type nonExpiringVerifier struct {
	signature.Verifier
}

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool {
	return true
}

func trustedPublicKeyMaterial(pk crypto.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadECDSAVerifier(pk.(*ecdsa.PublicKey), crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{verifier}, nil
	})
}
