// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/digitorus/timestamp"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/rekor/pkg/types/intoto"
	"github.com/sigstore/rekor/pkg/types/rekord"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	tsx509 "github.com/sigstore/timestamp-authority/pkg/x509"
)

var (
	// OIDExtensionCTPoison is defined in RFC 6962 s3.1.
	OIDExtensionCTPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	// OIDExtensionCTSCT is defined in RFC 6962 s3.3.
	OIDExtensionCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

type VirtualSigstore struct {
	fulcioCA              *root.FulcioCertificateAuthority
	fulcioIntermediateKey *ecdsa.PrivateKey
	tsaCA                 *root.SigstoreTimestampingAuthority
	tsaLeafKey            *ecdsa.PrivateKey
	rekorKey              *ecdsa.PrivateKey
	ctlogKey              *ecdsa.PrivateKey
	publicKeyVerifier     map[string]root.TimeConstrainedVerifier
}

func NewVirtualSigstore() (*VirtualSigstore, error) {
	ss := &VirtualSigstore{fulcioCA: &root.FulcioCertificateAuthority{}, tsaCA: &root.SigstoreTimestampingAuthority{}}

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

	ss.rekorKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	ss.ctlogKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

// getLogID calculates the digest of a PKIX-encoded public key
func getLogID(pub crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(pubBytes)
	return hex.EncodeToString(digest[:]), nil
}

func (ca *VirtualSigstore) RekorLogID() (string, error) {
	return getLogID(ca.rekorKey.Public())
}

func (ca *VirtualSigstore) RekorSignPayload(payload tlog.RekorPayload) ([]byte, error) {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	canonicalized, err := jsoncanonicalizer.Transform(jsonPayload)
	if err != nil {
		return nil, err
	}
	signer, err := signature.LoadECDSASignerVerifier(ca.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	bundleSig, err := signer.SignMessage(bytes.NewReader(canonicalized))
	if err != nil {
		return nil, err
	}
	return bundleSig, nil
}

func (ca *VirtualSigstore) GenerateLeafCert(identity, issuer string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leafCert, err := GenerateLeafCert(identity, issuer, time.Now(), privKey, ca.fulcioCA.Intermediates[0], ca.fulcioIntermediateKey, ca.ctlogKey)
	if err != nil {
		return nil, nil, err
	}
	return leafCert, privKey, nil
}

func (ca *VirtualSigstore) Attest(identity, issuer string, envelopeBody []byte) (*TestEntity, error) {
	// The timing here is important. We need to attest at a time when the leaf
	// certificate is valid, so we match what GenerateLeafCert() does, above
	return ca.AttestAtTime(identity, issuer, envelopeBody, time.Now().Add(5*time.Minute), false)
}

func (ca *VirtualSigstore) AttestAtTime(identity, issuer string, envelopeBody []byte, integratedTime time.Time, generateInclusionProof bool) (*TestEntity, error) {
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

	envelope, err := dsseSigner.SignPayload(context.TODO(), "application/vnd.in-toto+json", envelopeBody)
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

	entry, err := ca.GenerateTlogEntry(leafCert, envelope, sig, integratedTime.Unix(), generateInclusionProof)
	if err != nil {
		return nil, err
	}

	return &TestEntity{
		certChain:   []*x509.Certificate{leafCert, ca.fulcioCA.Intermediates[0], ca.fulcioCA.Root},
		timestamps:  [][]byte{tsr},
		envelope:    envelope,
		tlogEntries: []*tlog.Entry{entry},
	}, nil
}

func (ca *VirtualSigstore) Sign(identity, issuer string, artifact []byte) (*TestEntity, error) {
	return ca.SignAtTime(identity, issuer, artifact, time.Now().Add(5*time.Minute))
}

func (ca *VirtualSigstore) SignAtTime(identity, issuer string, artifact []byte, integratedTime time.Time) (*TestEntity, error) {
	leafCert, leafPrivKey, err := ca.GenerateLeafCert(identity, issuer)
	if err != nil {
		return nil, err
	}

	signer, err := signature.LoadECDSASignerVerifier(leafPrivKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(artifact)
	sig, err := signer.SignMessage(bytes.NewReader(artifact))
	if err != nil {
		return nil, err
	}

	tsr, err := generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
	if err != nil {
		return nil, err
	}

	entry, err := ca.generateTlogEntryHashedRekord(leafCert, artifact, sig, integratedTime.Unix())
	if err != nil {
		return nil, err
	}

	return &TestEntity{
		certChain:        []*x509.Certificate{leafCert, ca.fulcioCA.Intermediates[0], ca.fulcioCA.Root},
		timestamps:       [][]byte{tsr},
		messageSignature: bundle.NewMessageSignature(digest[:], "SHA2_256", sig),
		tlogEntries:      []*tlog.Entry{entry},
	}, nil
}

func (ca *VirtualSigstore) GenerateTlogEntry(leafCert *x509.Certificate, envelope *dsse.Envelope, sig []byte, integratedTime int64, generateInclusionProof bool) (*tlog.Entry, error) {
	leafCertPem, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		return nil, err
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	rekorBody, err := generateRekorEntry(intoto.KIND, intoto.New().DefaultVersion(), envelopeBytes, leafCertPem, sig)
	if err != nil {
		return nil, err
	}

	rekorLogID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		return nil, err
	}

	rekorLogIDRaw, err := hex.DecodeString(rekorLogID)
	if err != nil {
		return nil, err
	}

	logIndex := int64(0)

	b := createRekorBundle(rekorLogID, integratedTime, logIndex, rekorBody)
	set, err := ca.RekorSignPayload(*b)
	if err != nil {
		return nil, err
	}

	rekorBodyRaw, err := base64.StdEncoding.DecodeString(rekorBody)
	if err != nil {
		return nil, err
	}

	var inclusionProof *models.InclusionProof
	if generateInclusionProof {
		inclusionProof, err = ca.GetInclusionProof(rekorBodyRaw)
		if err != nil {
			return nil, err
		}
	}
	return tlog.NewEntry(rekorBodyRaw, integratedTime, logIndex, rekorLogIDRaw, set, inclusionProof)
}

func (ca *VirtualSigstore) GetInclusionProof(rekorBodyRaw []byte) (*models.InclusionProof, error) {
	signer, err := signature.LoadECDSASignerVerifier(ca.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	rootHash := sha256.Sum256(append([]byte("\000"), rekorBodyRaw...))
	encodedRootHash := hex.EncodeToString(rootHash[:])
	scBytes, err := util.CreateAndSignCheckpoint(context.TODO(), "rekor.localhost", int64(123), uint64(42), rootHash[:], signer)
	if err != nil {
		return nil, err
	}

	return &models.InclusionProof{
		TreeSize:   swag.Int64(int64(1)),
		RootHash:   &encodedRootHash,
		LogIndex:   swag.Int64(0),
		Hashes:     nil,
		Checkpoint: swag.String(string(scBytes)),
	}, nil
}

func (ca *VirtualSigstore) generateTlogEntryHashedRekord(leafCert *x509.Certificate, artifact []byte, sig []byte, integratedTime int64) (*tlog.Entry, error) {
	leafCertPem, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		return nil, err
	}

	rekorBody, err := generateRekorEntry(hashedrekord.KIND, hashedrekord.New().DefaultVersion(), artifact, leafCertPem, sig)
	if err != nil {
		return nil, err
	}

	rekorLogID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		return nil, err
	}

	rekorLogIDRaw, err := hex.DecodeString(rekorLogID)
	if err != nil {
		return nil, err
	}

	logIndex := int64(1000)

	b := createRekorBundle(rekorLogID, integratedTime, logIndex, rekorBody)
	set, err := ca.RekorSignPayload(*b)
	if err != nil {
		return nil, err
	}

	rekorBodyRaw, err := base64.StdEncoding.DecodeString(rekorBody)
	if err != nil {
		return nil, err
	}

	return tlog.NewEntry(rekorBodyRaw, integratedTime, logIndex, rekorLogIDRaw, set, nil)
}

func (ca *VirtualSigstore) PublicKeyVerifier(keyID string) (root.TimeConstrainedVerifier, error) {
	v, ok := ca.publicKeyVerifier[keyID]
	if !ok {
		return nil, fmt.Errorf("public key not found for keyID: %s", keyID)
	}
	return v, nil
}

func generateRekorEntry(kind, version string, artifact []byte, cert []byte, sig []byte) (string, error) {
	// Generate the Rekor Entry
	entryImpl, err := createEntry(context.Background(), kind, version, artifact, cert, sig)
	if err != nil {
		return "", err
	}
	entryBytes, err := entryImpl.Canonicalize(context.Background())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(entryBytes), nil
}

func createEntry(ctx context.Context, kind, apiVersion string, blobBytes, certBytes, sigBytes []byte) (types.EntryImpl, error) {
	props := types.ArtifactProperties{
		PublicKeyBytes: [][]byte{certBytes},
		PKIFormat:      string(pki.X509),
	}
	switch kind {
	case rekord.KIND, intoto.KIND:
		props.ArtifactBytes = blobBytes
		props.SignatureBytes = sigBytes
	case hashedrekord.KIND:
		blobHash := sha256.Sum256(blobBytes)
		props.ArtifactHash = strings.ToLower(hex.EncodeToString(blobHash[:]))
		props.SignatureBytes = sigBytes
	default:
		return nil, fmt.Errorf("unexpected entry kind: %s", kind)
	}
	proposedEntry, err := types.NewProposedEntry(ctx, kind, apiVersion, props)
	if err != nil {
		return nil, err
	}
	eimpl, err := types.CreateVersionedEntry(proposedEntry)
	if err != nil {
		return nil, err
	}

	can, err := types.CanonicalizeEntry(ctx, eimpl)
	if err != nil {
		return nil, err
	}
	proposedEntryCan, err := models.UnmarshalProposedEntry(bytes.NewReader(can), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	return types.UnmarshalEntry(proposedEntryCan)
}

func createRekorBundle(logID string, integratedTime int64, logIndex int64, rekorEntry string) *tlog.RekorPayload {
	return &tlog.RekorPayload{
		LogID:          logID,
		IntegratedTime: integratedTime,
		LogIndex:       logIndex,
		Body:           rekorEntry,
	}
}

func (ca *VirtualSigstore) TimestampResponse(sig []byte) ([]byte, error) {
	return generateTimestampingResponse(sig, ca.tsaCA.Leaf, ca.tsaLeafKey)
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

	return tsTemplate.CreateResponseWithOpts(tsaCert, tsaKey, hash)
}

func (ca *VirtualSigstore) TimestampingAuthorities() []root.TimestampingAuthority {
	return []root.TimestampingAuthority{ca.tsaCA}
}

func (ca *VirtualSigstore) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{ca.fulcioCA}
}

func (ca *VirtualSigstore) RekorLogs() map[string]*root.TransparencyLog {
	verifiers := make(map[string]*root.TransparencyLog)
	logID, err := getLogID(ca.rekorKey.Public())
	if err != nil {
		panic(err)
	}
	verifiers[logID] = &root.TransparencyLog{
		BaseURL:             "test",
		ID:                  []byte(logID),
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(time.Hour),
		HashFunc:            crypto.SHA256,
		PublicKey:           ca.rekorKey.Public(),
		SignatureHashFunc:   crypto.SHA256,
	}
	return verifiers
}

func (ca *VirtualSigstore) CTLogs() map[string]*root.TransparencyLog {
	verifiers := make(map[string]*root.TransparencyLog)
	logID, err := getLogID(ca.ctlogKey.Public())
	if err != nil {
		panic(err)
	}
	verifiers[logID] = &root.TransparencyLog{
		BaseURL:             "test",
		ID:                  []byte(logID),
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(time.Hour),
		HashFunc:            crypto.SHA256,
		PublicKey:           ca.ctlogKey.Public(),
	}
	return verifiers
}

type TestEntity struct {
	certChain        []*x509.Certificate
	envelope         *dsse.Envelope
	messageSignature *bundle.MessageSignature
	timestamps       [][]byte
	tlogEntries      []*tlog.Entry
}

func (e *TestEntity) VerificationContent() (verify.VerificationContent, error) {
	return &bundle.Certificate{Certificate: e.certChain[0]}, nil
}

func (e *TestEntity) HasInclusionPromise() bool {
	return true
}

func (e *TestEntity) HasInclusionProof() bool {
	for _, tlog := range e.tlogEntries {
		if tlog.HasInclusionProof() {
			return true
		}
	}
	return false
}

func (e *TestEntity) SignatureContent() (verify.SignatureContent, error) {
	if e.envelope != nil {
		return &bundle.Envelope{Envelope: e.envelope}, nil
	}
	return e.messageSignature, nil
}

func (e *TestEntity) Timestamps() ([][]byte, error) {
	return e.timestamps, nil
}

func (e *TestEntity) TlogEntries() ([]*tlog.Entry, error) {
	return e.tlogEntries, nil
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
	parentTemplate *x509.Certificate, parentPriv crypto.Signer, sctKey crypto.Signer) (*x509.Certificate, error) {

	skid, err := cryptoutils.SKID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	certTemplate := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{subject},
		NotBefore:      expiration,
		NotAfter:       expiration.Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:           false,
		ExtraExtensions: []pkix.Extension{
			{
				// OID for OIDC Issuer extension
				Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
				Critical: false,
				Value:    []byte(oidcIssuer),
			},
			{
				// Poison extension for pre-certificate
				Id:       OIDExtensionCTPoison,
				Critical: true,
				Value:    asn1.NullBytes,
			},
		},
		SubjectKeyId: skid,
	}

	cert, err := createCertificate(certTemplate, parentTemplate, &priv.PublicKey, parentPriv)
	if err != nil {
		return nil, err
	}

	logID, err := ctfe.GetCTLogID(sctKey.Public())
	if err != nil {
		return nil, err
	}

	return embedSCTs(cert, parentTemplate, parentPriv, &priv.PublicKey, sctKey, []ct.SignedCertificateTimestamp{
		{
			SCTVersion: ct.V1,
			Timestamp:  12345,
			LogID:      ct.LogID{KeyID: logID},
		},
	})
}

func embedSCTs(preCert *x509.Certificate, parentCert *x509.Certificate, parentPriv crypto.Signer, pk crypto.PublicKey, sctKey crypto.Signer, sctInput []ct.SignedCertificateTimestamp) (*x509.Certificate, error) {
	scts := make([]*ct.SignedCertificateTimestamp, len(sctInput))
	for i, s := range sctInput {
		logEntry := ct.LogEntry{
			Leaf: ct.MerkleTreeLeaf{
				Version:  ct.V1,
				LeafType: ct.TimestampedEntryLeafType,
				TimestampedEntry: &ct.TimestampedEntry{
					Timestamp: s.Timestamp,
					EntryType: ct.PrecertLogEntryType,
					PrecertEntry: &ct.PreCert{
						IssuerKeyHash:  sha256.Sum256(parentCert.RawSubjectPublicKeyInfo),
						TBSCertificate: preCert.RawTBSCertificate,
					},
				},
			},
		}
		data, err := ct.SerializeSCTSignatureInput(s, logEntry)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(data)
		signature, err := sctKey.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		scts[i] = &ct.SignedCertificateTimestamp{
			SCTVersion: s.SCTVersion,
			LogID:      s.LogID,
			Timestamp:  s.Timestamp,
			Signature: ct.DigitallySigned{
				Algorithm: tls.SignatureAndHashAlgorithm{
					Hash:      tls.SHA256,
					Signature: tls.ECDSA,
				},
				Signature: signature,
			},
		}
	}
	sctList, err := ctx509util.MarshalSCTsIntoSCTList(scts)
	if err != nil {
		return nil, err
	}
	sctBytes, err := tls.Marshal(*sctList)
	if err != nil {
		return nil, err
	}
	asnSCT, err := asn1.Marshal(sctBytes)
	if err != nil {
		return nil, err
	}
	var exts []pkix.Extension
	for _, pext := range preCert.Extensions {
		if !pext.Id.Equal(OIDExtensionCTPoison) {
			exts = append(exts, pext)
		}
	}
	exts = append(exts, pkix.Extension{
		Id:    OIDExtensionCTSCT,
		Value: asnSCT,
	})
	preCert.ExtraExtensions = exts
	certDERBytes, err := x509.CreateCertificate(rand.Reader, preCert, parentCert, pk, parentPriv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certDERBytes)
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
