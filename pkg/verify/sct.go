package verify

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/google/certificate-transparency-go/ctutil"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

func VerifySignedCertificateTimestamp(leafCert *x509.Certificate, threshold int, trustedMaterial root.TrustedMaterial) error {
	ctlogs := trustedMaterial.CTlogAuthorities()
	fulcioCerts := trustedMaterial.FulcioCertificateAuthorities()

	scts, err := x509util.ParseSCTsFromCertificate(leafCert.Raw)
	if err != nil {
		return err
	}

	certChain, err := ctx509.ParseCertificates(leafCert.Raw)
	if err != nil {
		return err
	}

	verified := 0
	for _, sct := range scts {
		encodedKeyID := hex.EncodeToString(sct.LogID.KeyID[:])
		key, ok := ctlogs[encodedKeyID]
		if !ok {
			return fmt.Errorf("Unable to find ctlogs key for %s", encodedKeyID)
		}

		for _, fulcioCa := range fulcioCerts {
			if len(fulcioCa.Intermediates) == 0 {
				continue
			}
			fulcioIssuer, err := ctx509.ParseCertificates(fulcioCa.Intermediates[0].Raw)
			if err != nil {
				continue
			}

			fulcioChain := make([]*ctx509.Certificate, len(certChain))
			copy(fulcioChain, certChain)
			fulcioChain = append(fulcioChain, fulcioIssuer...)

			err = ctutil.VerifySCT(key.PublicKey, fulcioChain, sct, true)
			if err == nil {
				verified++
			}
		}
	}

	if verified < threshold {
		return fmt.Errorf("Only able to verify %d SCT entries; unable to meet threshold of %d", verified, threshold)
	}

	return nil

}
