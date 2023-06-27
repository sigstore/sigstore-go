package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tuf"
	"github.com/github/sigstore-verifier/pkg/verifier"
)

var expectedOIDC *string
var expectedSAN *string
var requireTSA *bool
var requireTlog *bool
var trustedrootJSONpath *string
var tufRootURL *string

func init() {
	expectedOIDC = flag.String("expectedOIDC", "", "The expected OIDC issuer for the signing certificate")
	expectedSAN = flag.String("expectedSAN", "", "The expected identity in the signing certificate's SAN extension")
	requireTSA = flag.Bool("requireTSA", false, "Require RFC 3161 signed timestamp")
	requireTlog = flag.Bool("requireTlog", true, "Require Artifact Transparency log entry (Rekor)")
	trustedrootJSONpath = flag.String("trustedrootJSONpath", "examples/trusted-root-public-good.json", "Path to trustedroot JSON file")
	tufRootURL = flag.String("tufRootURL", "", "URL of TUF root containing trusted root JSON file")
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

	opts := verifier.GetDefaultOptions()
	opts.TsaOptions.Disable = !*requireTSA
	opts.TlogOptions.Disable = !*requireTlog
	if *expectedOIDC != "" {
		verifier.SetExpectedOIDC(opts, *expectedOIDC)
	}
	if *expectedSAN != "" {
		verifier.SetExpectedSAN(opts, *expectedSAN)
	}

	var tr *root.ParsedTrustedRoot
	var trustedrootJSON []byte

	if *tufRootURL != "" {
		trustedrootJSON, err = tuf.GetTrustedrootJSON(*tufRootURL, "tufdata")
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

	tr, err = root.NewTrustedRootFromJSON(trustedrootJSON)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	p := verifier.NewTrustedRootVerifier(tr, opts)
	err = p.Verify(b)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Verification successful!")
}
