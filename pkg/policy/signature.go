package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

type EnvelopeSignaturePolicy struct {
	verifier dsse.EnvelopeVerifier
}

func (p *EnvelopeSignaturePolicy) VerifyPolicy(entity SignedEntity) error {
	envelope, err := entity.Envelope()
	if err != nil {
		return errors.New("entity does not provide an envelope")
	}
	_, err = p.verifier.Verify(context.TODO(), envelope)
	if err != nil {
		return fmt.Errorf("envelope verification failed: %w", err)
	}
	return nil
}

type EnvelopeCertificateSignaturePolicy struct{}

func (p *EnvelopeCertificateSignaturePolicy) VerifyPolicy(entity SignedEntity) error {
	envelope, err := entity.Envelope()
	if err != nil {
		return errors.New("entity does not provide an envelope")
	}

	certificateChain, err := entity.CertificateChain()
	if err != nil {
		return errors.New("entity does not provide a certificate")
	}

	// TODO: verify envelope with certificate
	_, _ = envelope, certificateChain
	return nil
}

type MappedEnvelopeSignaturePolicy struct {
	verifierMapping map[string]*dsse.EnvelopeVerifier
}

func NewMappedEnvelopeSignaturePolicy(verifierMapping map[string]*dsse.EnvelopeVerifier) *MappedEnvelopeSignaturePolicy {
	return &MappedEnvelopeSignaturePolicy{verifierMapping: verifierMapping}
}

func NewMappedEnvelopeSignaturePolicyFromKeys(keyMap map[string]*ecdsa.PublicKey) (*MappedEnvelopeSignaturePolicy, error) {
	verifierMapping := make(map[string]*dsse.EnvelopeVerifier)
	for keyID, key := range keyMap {
		verifier, err := signature.LoadECDSAVerifier(key, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		pub, err := verifier.PublicKey()
		if err != nil {
			return nil, err
		}
		envVerifier, err := dsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{
			SignatureVerifier: verifier,
			Pub:               pub,
		})
		if err != nil {
			return nil, err
		}
		verifierMapping[keyID] = envVerifier
	}
	return &MappedEnvelopeSignaturePolicy{verifierMapping}, nil
}

func (p *MappedEnvelopeSignaturePolicy) VerifyPolicy(entity SignedEntity) error {
	envelope, err := entity.Envelope()
	if err != nil {
		return errors.New("entity does not provide an envelope")
	}

	keyID, err := entity.KeyID()
	if err != nil {
		return errors.New("entity does not provide a key id")
	}

	if verifier, ok := p.verifierMapping[keyID]; ok {
		_, err = verifier.Verify(context.TODO(), envelope)
		if err != nil {
			return errors.New("envelope signature verification failed")
		}
	} else {
		return errors.New("could not find verifier for given key ID")
	}

	return nil
}
