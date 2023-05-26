package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/policy"
	"github.com/github/sigstore-verifier/pkg/root"
)

var requireTSA *bool
var requireTlog *bool
var trustedrootJSONpath *string

func init() {
	requireTSA = flag.Bool("requireTSA", false, "Require RFC 3161 signed timestamp")
	requireTlog = flag.Bool("requireTlog", true, "Require Artifact Transparency log entry (Rekor)")
	trustedrootJSONpath = flag.String("trustedrootJSONpath", "", "Path to trustedroot JSON file")
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

	opts := root.GetDefaultOptions()
	opts.TsaOptions.Disable = !*requireTSA
	opts.TlogOptions.Disable = !*requireTlog

	var tr *root.TrustedRoot
	if *trustedrootJSONpath != "" {
		trustedrootJSON, err := os.ReadFile(*trustedrootJSONpath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		tr, err = root.NewTrustedRootFromJSON(trustedrootJSON)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		tr, err = root.GetDefaultTrustedRoot()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	p := policy.NewTrustedRootPolicy(tr, opts)
	err = p.VerifyPolicy(b)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Verification successful!")
}
