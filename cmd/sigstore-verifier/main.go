package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/github/sigstore-verifier/pkg/bundle"
	"github.com/github/sigstore-verifier/pkg/policy"
)

func init() {
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
	bundleFile, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer bundleFile.Close()

	bundleBytes, err := ioutil.ReadAll(bundleFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var b bundle.ProtobufBundle
	err = b.UnmarshalJSON(bundleBytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = policy.VerifyKeyless(&b)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Verification successful!")
}
