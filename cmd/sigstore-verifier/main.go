package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/policy"
	protoverification "github.com/sigstore/protobuf-specs/gen/pb-go/verification/v1"
)

var requireTSA *bool

func init() {
	requireTSA = flag.Bool("requireTSA", false, "Require RFC 3161 signed timestamp")
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

	if !*requireTSA {
		err = policy.VerifyKeyless(b)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	} else {
		opts := &protoverification.ArtifactVerificationOptions{
			Signers: nil,
			TlogOptions: &protoverification.ArtifactVerificationOptions_TlogOptions{
				Threshold:                 0,
				PerformOnlineVerification: false,
				Disable:                   true,
			},
			CtlogOptions: &protoverification.ArtifactVerificationOptions_CtlogOptions{
				Threshold:   0,
				DetachedSct: false,
				Disable:     true,
			},
			TsaOptions: &protoverification.ArtifactVerificationOptions_TimestampAuthorityOptions{
				Threshold: 1,
				Disable:   false,
			},
		}

		p, err := policy.NewSigstorePolicyWithOpts(opts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		err = p.VerifyPolicy(b)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	fmt.Println("Verification successful!")
}
