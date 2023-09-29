package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"

	"github.com/github/sigstore-go/pkg/bundle"
	"github.com/github/sigstore-go/pkg/root"
	"github.com/github/sigstore-go/pkg/tuf"
	"github.com/github/sigstore-go/pkg/verify"
)

var bundlePath *string
var certPath *string
var certOIDC *string
var certSAN *string
var signaturePath *string

func usage() {
	fmt.Println("Usage:")
	fmt.Printf("\t%s verify --signature FILE --certificate FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL FILE\n", os.Args[0])
	fmt.Printf("\t%s verify-bundle --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL FILE\n", os.Args[0])
}

func main() {
	if len(os.Args) < 8 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "verify":
		for i := 2; i < len(os.Args); i += 2 {
			switch os.Args[i] {
			case "--certificate":
				certPath = &os.Args[i+1]
			case "--certificate-oidc-issuer":
				certOIDC = &os.Args[i+1]
			case "--certificate-identity":
				certSAN = &os.Args[i+1]
			case "--signature":
				signaturePath = &os.Args[i+1]
			}
		}

		// Load certificate
		cert, err := os.ReadFile(*certPath)
		if err != nil {
			log.Fatalf("unable to open certificate file %s", *certPath)
		}

		pemCert, _ := pem.Decode(cert)
		if pemCert == nil {
			log.Fatalf("unable to load cerficate from %s", *certPath)
		}

		// Load signature
		sig, err := os.ReadFile(*signaturePath)
		if err != nil {
			log.Fatalf("unable to open signature file %s", *signaturePath)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(string(sig))
		if err != nil {
			log.Fatal(err)
		}

		fileBytes, err := os.ReadFile(os.Args[len(os.Args)-1])
		if err != nil {
			log.Fatal(err)
		}

		fileDigest := sha256.Sum256(fileBytes)

		// Construct bundle
		signingCert := protocommon.X509Certificate{
			RawBytes: pemCert.Bytes,
		}

		pb := protobundle.Bundle{
			MediaType: bundle.SigstoreBundleMediaType01,
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{&signingCert},
					},
				},
			},
			Content: &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{
					MessageDigest: &protocommon.HashOutput{
						Algorithm: protocommon.HashAlgorithm_SHA2_256,
						Digest:    fileDigest[:],
					},
					Signature: sigBytes,
				},
			},
		}

		policyConfig := []verify.PolicyOptionConfigurator{}
		if *certOIDC != "" || *certSAN != "" {
			certID, err := verify.NewShortCertificateIdentity(*certOIDC, *certSAN, "", "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			policyConfig = append(policyConfig, verify.WithCertificateIdentity(certID))
		}

		// Load trust root
		_, filename, _, ok := runtime.Caller(1)
		if !ok {
			log.Fatal("unable to get path")
		}

		tufDir := path.Join(path.Dir(filename), "tufdata")

		trustedrootJSON, err := tuf.GetTrustedrootJSON("tuf-repo-cdn.sigstore.dev", tufDir)
		if err != nil {
			log.Fatal(err)
		}

		tr, err := root.NewTrustedRootFromJSON(trustedrootJSON)
		if err != nil {
			log.Fatal(err)
		}

		// Verify bundle
		sev, err := verify.NewSignedEntityVerifier(tr, verify.WithoutAnyObserverTimestampsInsecure())
		if err != nil {
			log.Fatal(err)
		}

		bun, err := bundle.NewProtobufBundle(&pb)
		if err != nil {
			log.Fatal(err)
		}

		_, err = sev.Verify(bun, policyConfig...)
		if err != nil {
			log.Fatal(err)
		}
	case "verify-bundle":
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

		// Load artifact
		file, err := os.Open(os.Args[len(os.Args)-1])
		if err != nil {
			log.Fatal(err)
		}

		// Configure verification options
		policyConfig := []verify.PolicyOptionConfigurator{verify.WithArtifact(file)}
		if *certOIDC != "" || *certSAN != "" {
			certID, err := verify.NewShortCertificateIdentity(*certOIDC, *certSAN, "", "")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			policyConfig = append(policyConfig, verify.WithCertificateIdentity(certID))
		}

		// Load trust root
		_, filename, _, ok := runtime.Caller(1)
		if !ok {
			log.Fatal("unable to get path")
		}

		tufDir := path.Join(path.Dir(filename), "tufdata")

		trustedrootJSON, err := tuf.GetTrustedrootJSON("tuf-repo-cdn.sigstore.dev", tufDir)
		if err != nil {
			log.Fatal(err)
		}

		tr, err := root.NewTrustedRootFromJSON(trustedrootJSON)
		if err != nil {
			log.Fatal(err)
		}

		// Verify bundle
		sev, err := verify.NewSignedEntityVerifier(tr, verify.WithTransparencyLog(1), verify.WithSignedCertificateTimestamps(1))
		if err != nil {
			log.Fatal(err)
		}

		_, err = sev.Verify(b, policyConfig...)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("Unsupported command %s", os.Args[1])
	}
}
