// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/ear"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/vts/appraisal"
)

// The fixtures are real collections from a Dell XE9780 iDRAC fronting an HGX
// B300 baseboard (wdl101-b300-mach2, HGX_IRoT_GPU_0, 2026-09-09), taken by
// fsattest after its latch-aware Dell adapter existed.
//
//	bound:           the signed request carries the nonce the collector sent
//	foreign-request: the payload answers a request the collector never made
const (
	fixtureBound   = "hgx-irot-gpu0-bound.json"
	fixtureForeign = "hgx-irot-gpu0-foreign-request.json"
	nvidiaRoot     = "nvidia-device-identity-ca.pem"
)

func loadBundle(t *testing.T, name string) *Bundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var b Bundle
	require.NoError(t, json.Unmarshal(raw, &b))
	return &b
}

func encode(t *testing.T, b *Bundle) []byte {
	t.Helper()
	data, err := cbor.Marshal(b)
	require.NoError(t, err)
	return data
}

// evidenceFor submits a bundle to a session whose nonce is sessionNonce.
func evidenceFor(t *testing.T, b *Bundle, sessionNonce []byte) *appraisal.Evidence {
	t.Helper()
	return &appraisal.Evidence{
		MediaType: EvidenceMediaType,
		Data:      encode(t, b),
		Nonce:     sessionNonce,
	}
}

func trustAnchorFromPEM(t *testing.T, pemText string) []*comid.KeyTriple {
	t.Helper()
	key, err := comid.NewPKIXBase64Cert(pemText)
	require.NoError(t, err)
	return []*comid.KeyTriple{{VerifKeys: comid.CryptoKeys{key}}}
}

func nvidiaTrustAnchor(t *testing.T) []*comid.KeyTriple {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", nvidiaRoot))
	require.NoError(t, err)
	return trustAnchorFromPEM(t, string(raw))
}

// impostorRoot is a self-signed CA with the NVIDIA root's exact subject and a
// different key: what an attacker would provision under the same lookup key.
func impostorRoot(t *testing.T) []*comid.KeyTriple {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"NVIDIA"}, CommonName: "NVIDIA Device Identity CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return trustAnchorFromPEM(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

func freshNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 32)
	_, err := rand.Read(n)
	require.NoError(t, err)
	return n
}

func requireBadEvidence(t *testing.T, err error, contains string) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, handler.BadEvidenceError{})
	assert.Contains(t, err.Error(), contains)
}

func TestGetTrustAnchorIDs_KeyedByChainRootSubject(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	ids, err := NewImplementation().GetTrustAnchorIDs(evidenceFor(t, b, b.Nonce))
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.Equal(t, "NVIDIA", *ids[0].Class.Vendor)
	assert.Equal(t, "NVIDIA Device Identity CA", *ids[0].Class.Model)
	assert.Nil(t, ids[0].Instance)
}

func TestValidateEvidenceIntegrity_HardwareFixtureVerifies(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	// The fixture's session nonce is the one the collector sent, which is how
	// a real submission works: the verifier issues it, the device signs it.
	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, b.Nonce), nvidiaTrustAnchor(t), nil)
	require.NoError(t, err)
}

func TestValidateEvidenceIntegrity_ReplayToAnotherSessionFails(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, freshNonce(t)), nvidiaTrustAnchor(t), nil)
	requireBadEvidence(t, err, "session's nonce")
}

func TestValidateEvidenceIntegrity_EditedBundleNonceDoesNotHelp(t *testing.T) {
	// A replayer rewrites the unsigned bundle nonce to the new session's. The
	// signed request still carries the original, so it must still fail.
	b := loadBundle(t, fixtureBound)
	session := freshNonce(t)
	b.Nonce = session

	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, session), nvidiaTrustAnchor(t), nil)
	requireBadEvidence(t, err, "session's nonce")
}

func TestValidateEvidenceIntegrity_ForeignRequestFails(t *testing.T) {
	// Genuine signature, but over a request this collector never made; the
	// latch handed back someone else's exchange.
	b := loadBundle(t, fixtureForeign)

	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, b.Nonce), nvidiaTrustAnchor(t), nil)
	requireBadEvidence(t, err, "session's nonce")
}

func TestValidateEvidenceIntegrity_ImpostorRootWithSameSubjectFails(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, b.Nonce), impostorRoot(t), nil)
	requireBadEvidence(t, err, "trust anchor")
}

func TestValidateEvidenceIntegrity_TamperedMeasurementsFail(t *testing.T) {
	b := loadBundle(t, fixtureBound)
	// Flip a byte inside the measurement record, well clear of the headers.
	b.SignedMeasurements[len(b.SignedMeasurements)/2] ^= 0x01

	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, b.Nonce), nvidiaTrustAnchor(t), nil)
	requireBadEvidence(t, err, "not verified")
}

func TestValidateEvidenceIntegrity_SessionNonceMustBeSPDMSized(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	err := NewImplementation().ValidateEvidenceIntegrity(
		evidenceFor(t, b, b.Nonce[:16]), nvidiaTrustAnchor(t), nil)
	requireBadEvidence(t, err, "32 bytes")
}

func TestValidateEvidenceIntegrity_RequiresExactlyOneTrustAnchor(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	err := NewImplementation().ValidateEvidenceIntegrity(evidenceFor(t, b, b.Nonce), nil, nil)
	requireBadEvidence(t, err, "trust anchor")
}

func TestExtractClaims_ReportsMeasurementsUnappraised(t *testing.T) {
	b := loadBundle(t, fixtureBound)

	claims, err := NewImplementation().ExtractClaims(evidenceFor(t, b, b.Nonce), nil)
	require.NoError(t, err)
	assert.Equal(t, "HGX_IRoT_GPU_0", claims["target-id"])
	assert.Equal(t, "wdl101-b300-mach2", claims["node-id"])
	assert.Equal(t, "1.1", claims["spdm-version"])
	assert.Equal(t, true, claims["request-in-payload"])
	assert.Equal(t, false, claims["transport-verified"])
	assert.NotEmpty(t, claims["measurements"])
}

func TestAppraiseClaims_GenuineHardwareOnly(t *testing.T) {
	result, err := NewImplementation().AppraiseClaims(map[string]any{}, nil)
	require.NoError(t, err)

	a := result.Submods[Descriptor.Name]
	assert.Equal(t, ear.GenuineHardwareClaim, a.TrustVector.Hardware)
	// Not compared against reference values, so no claim either way.
	assert.Equal(t, ear.NoClaim, a.TrustVector.Executables)
	assert.Equal(t, ear.NoClaim, a.TrustVector.Configuration)
	assert.Equal(t, ear.TrustTierAffirming, *a.Status)
}

func TestDecodeBundle_RejectsIncompleteAndUnknownSchema(t *testing.T) {
	b := loadBundle(t, fixtureBound)
	b.CertChain = nil
	_, err := decodeBundle(encode(t, b))
	assert.ErrorIs(t, err, ErrSchema)

	b = loadBundle(t, fixtureBound)
	b.SchemaVersion = "2"
	_, err = decodeBundle(encode(t, b))
	assert.ErrorIs(t, err, ErrSchema)
}
