package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/github/sigstore-verifier/pkg/root"
	"github.com/github/sigstore-verifier/pkg/tlog"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	tsx509 "github.com/sigstore/timestamp-authority/pkg/x509"
)

type VirtualSigstore struct {
	fulcioCA              root.CertificateAuthority
	fulcioIntermediateKey *ecdsa.PrivateKey
	tsaCA                 root.CertificateAuthority
	tsaLeafKey            *ecdsa.PrivateKey
}

func NewVirtualSigstore() (*VirtualSigstore, error) {
	ss := &VirtualSigstore{fulcioCA: root.CertificateAuthority{}, tsaCA: root.CertificateAuthority{}}

	rootCert, rootKey, err := GenerateRootCa()
	if err != nil {
		return nil, err
	}
	ss.fulcioCA.Root = rootCert
	ss.tsaCA.Root = rootCert

	intermediateCert, intermediateKey, _ := GenerateFulcioIntermediate(rootCert, rootKey)
	ss.fulcioCA.Intermediates = []*x509.Certificate{intermediateCert}
	ss.fulcioIntermediateKey = intermediateKey

	tsaIntermediateCert, tsaIntermediateKey, err := GenerateTSAIntermediate(rootCert, rootKey)
	if err != nil {
		return nil, err
	}
	ss.tsaCA.Intermediates = []*x509.Certificate{tsaIntermediateCert}
	tsaLeafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tsaLeafCert, err := GenerateTSALeafCert(time.Now().Add(-5*time.Minute), tsaLeafKey, tsaIntermediateCert, tsaIntermediateKey)
	if err != nil {
		return nil, err
	}
	ss.tsaCA.Leaf = tsaLeafCert
	ss.tsaLeafKey = tsaLeafKey

	ss.fulcioCA.ValidityPeriodStart = time.Now().Add(-5 * time.Hour)
	ss.fulcioCA.ValidityPeriodEnd = time.Now().Add(time.Hour)
	ss.tsaCA.ValidityPeriodStart = time.Now().Add(-5 * time.Hour)
	ss.tsaCA.ValidityPeriodEnd = time.Now().Add(time.Hour)

	return ss, nil
}

func (ca *VirtualSigstore) GenerateLeafCert(identity, issuer string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leafCert, err := GenerateLeafCert(identity, issuer, time.Now().Add(5*time.Minute), privKey, ca.fulcioCA.Intermediates[0], ca.fulcioIntermediateKey)
	if err != nil {
		return nil, nil, err
	}
	return leafCert, privKey, nil
}

func (ca *VirtualSigstore) Attest(identity, issuer string, envelopeBody []byte) (*TestEntity, error) {
	leafCert, leafPrivKey, err := ca.GenerateLeafCert(identity, issuer)
	if err != nil {
		return nil, err
	}

	signer, err := signature.LoadECDSASignerVerifier(leafPrivKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	dsseSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: signer,
		Pub:             leafCert.PublicKey.(*ecdsa.PublicKey),
	})
	if err != nil {
		return nil, err
	}

	envelope, err := dsseSigner.SignPayload(context.TODO(), "application/json", envelopeBody)
	if err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return nil, err
	}

	tsr, err := generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
	if err != nil {
		return nil, err
	}

	return &TestEntity{
		certChain:  []*x509.Certificate{leafCert, ca.fulcioCA.Intermediates[0], ca.fulcioCA.Root},
		timestamps: [][]byte{tsr},
		envelope:   envelope,
	}, nil
}

func generateTimestampingResponse(sig []byte, tsaCert *x509.Certificate, tsaKey *ecdsa.PrivateKey) ([]byte, error) {
	var hash crypto.Hash
	switch tsaKey.Curve {
	case elliptic.P256():
		hash = crypto.SHA256
	case elliptic.P384():
		hash = crypto.SHA384
	case elliptic.P521():
		hash = crypto.SHA512
	}
	tsq, err := timestamp.CreateRequest(bytes.NewReader(sig), &timestamp.RequestOptions{
		Hash: hash,
	})
	if err != nil {
		return nil, err
	}

	req, err := timestamp.ParseRequest([]byte(tsq))
	if err != nil {
		return nil, err
	}

	tsTemplate := timestamp.Timestamp{
		HashAlgorithm:   req.HashAlgorithm,
		HashedMessage:   req.HashedMessage,
		Time:            time.Now(),
		Policy:          asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:        false,
		Qualified:       false,
		ExtraExtensions: req.Extensions,
	}

	return tsTemplate.CreateResponse(tsaCert, tsaKey)
}

func (ca *VirtualSigstore) TSACertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{ca.tsaCA}
}

func (ca *VirtualSigstore) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{ca.fulcioCA}
}

type TestEntity struct {
	certChain   []*x509.Certificate
	envelope    *dsse.Envelope
	timestamps  [][]byte
	tlogEntries []*tlog.Entry
	keyID       string
}

func (e *TestEntity) CertificateChain() ([]*x509.Certificate, error) {
	return e.certChain, nil
}

func (e *TestEntity) Envelope() (*dsse.Envelope, error) {
	return e.envelope, nil
}

func (e *TestEntity) Timestamps() ([][]byte, error) {
	return e.timestamps, nil
}

func (e *TestEntity) TlogEntries() ([]*tlog.Entry, error) {
	return e.tlogEntries, nil
}

func (e *TestEntity) KeyID() (string, error) {
	return e.keyID, nil
}

// Much of the following code is adapted from cosign/test/cert_utils.go

func createCertificate(template *x509.Certificate, parent *x509.Certificate, pub interface{}, priv crypto.Signer) (*x509.Certificate, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func GenerateRootCa() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-5 * time.Hour),
		NotAfter:              time.Now().Add(5 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(rootTemplate, rootTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateFulcioIntermediate(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore-intermediate",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-2 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateTSAIntermediate(rootTemplate *x509.Certificate, rootPriv crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	subTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "sigstore-tsa-intermediate",
			Organization: []string{"sigstore.dev"},
		},
		NotBefore:             time.Now().Add(-2 * time.Minute),
		NotAfter:              time.Now().Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := createCertificate(subTemplate, rootTemplate, &priv.PublicKey, rootPriv)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func GenerateLeafCert(subject string, oidcIssuer string, expiration time.Time, priv *ecdsa.PrivateKey,
	parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, error) {
	certTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{subject},
		NotBefore:      expiration,
		NotAfter:       expiration.Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:           false,
		ExtraExtensions: []pkix.Extension{{
			// OID for OIDC Issuer extension
			Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Critical: false,
			Value:    []byte(oidcIssuer),
		},
		},
	}

	cert, err := createCertificate(certTemplate, parentTemplate, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func GenerateTSALeafCert(expiration time.Time, priv *ecdsa.PrivateKey, parentTemplate *x509.Certificate, parentPriv crypto.Signer) (*x509.Certificate, error) {
	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{tsx509.EKUTimestampingOID})
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    expiration,
		NotAfter:     expiration.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		IsCA:         false,
		// set EKU to x509.ExtKeyUsageTimeStamping but with a critical bit
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		},
	}

	cert, err := createCertificate(certTemplate, parentTemplate, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
