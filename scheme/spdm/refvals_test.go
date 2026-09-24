// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/ear"
	"github.com/veraison/swid"
)

// goldenFrom builds a reference-value triple holding, for the given indices,
// exactly what the fixture measured: the shape a captured CoRIM has.
func goldenFrom(t *testing.T, claims map[string]any, indices ...uint64) *comid.ValueTriple {
	t.Helper()
	obs, err := observedBlocks(claims)
	require.NoError(t, err)
	chip, class := claims["chip"].(string), claims["component-class"].(string)
	vt := &comid.ValueTriple{Environment: comid.Environment{Class: &comid.Class{Vendor: &chip, Model: &class}}}
	for _, idx := range indices {
		blk, ok := obs[idx]
		require.True(t, ok, "fixture has no block %d", idx)
		m, err := comid.NewUintMeasurement(idx)
		require.NoError(t, err)
		if blk.dmtfType&0x80 != 0 {
			m.SetRawValueBytes(blk.value, nil)
		} else {
			m.AddDigest(int(swid.Sha384), blk.value)
		}
		vt.Measurements.Add(m)
	}
	return vt
}

func gpuClaims(t *testing.T) map[string]any {
	t.Helper()
	b := loadBundle(t, fixtureBound)
	claims, err := NewImplementation().ExtractClaims(evidenceFor(t, b, b.Nonce), nil)
	require.NoError(t, err)
	// Round-trip through JSON, as claims cross the plugin RPC boundary.
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	var rt map[string]any
	require.NoError(t, json.Unmarshal(raw, &rt))
	return rt
}

func TestExtractClaims_KeysOnSignedChipAndClass(t *testing.T) {
	claims := gpuClaims(t)
	assert.Equal(t, "GB110 A01 FSP BROM", claims["chip"])
	assert.Equal(t, "HGX_IRoT_GPU", claims["component-class"])

	ids, err := NewImplementation().GetReferenceValueIDs(nil, claims)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	assert.Equal(t, "GB110 A01 FSP BROM", *ids[0].Class.Vendor)
	assert.Equal(t, "HGX_IRoT_GPU", *ids[0].Class.Model)
}

func TestAppraise_NoReferenceValuesLeavesMeasurementsUnscored(t *testing.T) {
	result, err := NewImplementation().AppraiseClaims(gpuClaims(t), nil)
	require.NoError(t, err)
	a := result.Submods[Descriptor.Name]
	assert.Equal(t, ear.NoClaim, a.TrustVector.Executables)
	assert.Equal(t, ear.NoClaim, a.TrustVector.Configuration)
	assert.Nil(t, a.VeraisonPolicyClaims)
}

func TestAppraise_MatchingReferenceValuesApprove(t *testing.T) {
	claims := gpuClaims(t)
	// 3-8 and 11-13 are digests (firmware and config), 1-2 raw.
	golden := goldenFrom(t, claims, 1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13)

	result, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{golden})
	require.NoError(t, err)
	a := result.Submods[Descriptor.Name]
	assert.Equal(t, ear.ApprovedRuntimeClaim, a.TrustVector.Executables)
	assert.Equal(t, ear.ApprovedConfigClaim, a.TrustVector.Configuration)
	assert.Equal(t, ear.TrustTierAffirming, *a.Status)

	rv := (*a.VeraisonPolicyClaims)["reference-values"].(map[string]any)
	assert.Equal(t, 11, rv["matched"])
	assert.Empty(t, rv["mismatched"])
	assert.Equal(t, 52-11, rv["unscored"])
}

func TestAppraise_FirmwareMismatchIsUnrecognizedAndNamed(t *testing.T) {
	claims := gpuClaims(t)
	golden := goldenFrom(t, claims, 4, 5, 7)
	// Index 4 is mutable firmware; expect a different build.
	d := &(*golden.Measurements.Values[0].Val.Digests)[0]
	d.Value = append([]byte{}, d.Value...)
	d.Value[0] ^= 0xFF

	result, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{golden})
	require.NoError(t, err)
	a := result.Submods[Descriptor.Name]
	assert.Equal(t, ear.UnrecognizedRuntimeClaim, a.TrustVector.Executables)
	assert.Equal(t, ear.ApprovedConfigClaim, a.TrustVector.Configuration) // 7 is firmware config
	assert.Equal(t, ear.TrustTierWarning, *a.Status)

	rv := (*a.VeraisonPolicyClaims)["reference-values"].(map[string]any)
	mm := rv["mismatched"].([]any)
	require.Len(t, mm, 1)
	entry := mm[0].(map[string]any)
	assert.Equal(t, uint64(4), entry["index"])
	assert.Equal(t, "executables", entry["claim"])
	assert.Equal(t, hex.EncodeToString(d.Value), entry["expected"])
}

func TestAppraise_ConfigMismatchIsUnsafeConfig(t *testing.T) {
	claims := gpuClaims(t)
	golden := goldenFrom(t, claims, 2) // raw hardware config
	raw := golden.Measurements.Values[0].Val.RawValue.Bytes()
	flipped := append([]byte{}, raw...)
	flipped[0] ^= 0x01
	golden.Measurements.Values[0].SetRawValueBytes(flipped, nil)

	result, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{golden})
	require.NoError(t, err)
	a := result.Submods[Descriptor.Name]
	assert.Equal(t, ear.UnsafeConfigClaim, a.TrustVector.Configuration)
	assert.Equal(t, ear.NoClaim, a.TrustVector.Executables)
}

func TestAppraise_AbsentBlockIsAMismatch(t *testing.T) {
	claims := gpuClaims(t)
	golden := goldenFrom(t, claims, 4)
	m, err := comid.NewUintMeasurement(uint64(200))
	require.NoError(t, err)
	m.SetRawValueBytes([]byte{0x01}, nil)
	golden.Measurements.Add(m)

	result, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{golden})
	require.NoError(t, err)
	rv := (*result.Submods[Descriptor.Name].VeraisonPolicyClaims)["reference-values"].(map[string]any)
	mm := rv["mismatched"].([]any)
	require.Len(t, mm, 1)
	assert.Equal(t, "absent", mm[0].(map[string]any)["observed"])
}

func TestReferenceValues_ConflictingEndorsementsRefused(t *testing.T) {
	claims := gpuClaims(t)
	a := goldenFrom(t, claims, 4)
	b := goldenFrom(t, claims, 4)
	d := &(*b.Measurements.Values[0].Val.Digests)[0]
	d.Value = append([]byte{}, d.Value...)
	d.Value[0] ^= 0xFF

	_, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{a, b})
	require.ErrorContains(t, err, "conflicting reference values for index 4")
}

func TestProfile_ReferenceValueShapeIsEnforced(t *testing.T) {
	chip, class := "GB110 A01 FSP BROM", "HGX_IRoT_GPU"
	good := comid.Environment{Class: &comid.Class{Vendor: &chip, Model: &class}}
	require.NoError(t, validateReferenceValueEnvironment(&good))

	noVendor := comid.Environment{Class: &comid.Class{Model: &class}}
	assert.Error(t, validateReferenceValueEnvironment(&noVendor))

	inst := comid.MustNewUEIDInstance(comid.TestUEID)
	withInstance := comid.Environment{Class: &comid.Class{Vendor: &chip, Model: &class}, Instance: inst}
	assert.Error(t, validateReferenceValueEnvironment(&withInstance))

	ok, err := comid.NewUintMeasurement(uint64(4))
	require.NoError(t, err)
	ok.AddDigest(int(swid.Sha384), make([]byte, 48))
	require.NoError(t, validateMeasurements([]comid.Measurement{*ok}))

	outOfRange, err := comid.NewUintMeasurement(uint64(255))
	require.NoError(t, err)
	outOfRange.SetRawValueBytes([]byte{1}, nil)
	assert.ErrorContains(t, validateMeasurements([]comid.Measurement{*outOfRange}), "out of range")

	both, err := comid.NewUintMeasurement(uint64(4))
	require.NoError(t, err)
	both.AddDigest(int(swid.Sha384), make([]byte, 48)).SetRawValueBytes([]byte{1}, nil)
	assert.ErrorContains(t, validateMeasurements([]comid.Measurement{*both}), "exactly one")
}

func vendorCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestAppraise_ProvenanceSeparatesVendorFromBaseline(t *testing.T) {
	claims := gpuClaims(t)
	// 4 and 5 are firmware; 7 is firmware configuration. Mark 4 as vendor-
	// authorized, the way values taken from a verified NVIDIA RIM are.
	golden := goldenFrom(t, claims, 4, 5, 7)
	k, err := comid.NewPKIXBase64Cert(vendorCertPEM(t, "RIM L4 Signer"))
	require.NoError(t, err)
	golden.Measurements.Values[0].AuthorizedBy = &comid.CryptoKeys{k}

	result, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{golden})
	require.NoError(t, err)
	a := result.Submods[Descriptor.Name]
	// Baseline matches are still known good, by policy.
	assert.Equal(t, ear.ApprovedRuntimeClaim, a.TrustVector.Executables)
	assert.Equal(t, ear.ApprovedConfigClaim, a.TrustVector.Configuration)

	rv := (*a.VeraisonPolicyClaims)["reference-values"].(map[string]any)
	prov := rv["provenance"].(map[string]any)
	assert.Equal(t, map[string]any{"vendor-backed": 1, "baseline": 1}, prov["executables"])
	assert.Equal(t, map[string]any{"vendor-backed": 0, "baseline": 1}, prov["configuration"])
	assert.Equal(t, []string{"RIM L4 Signer"}, prov["vendors"])
}

func TestAppraise_NoAuthorizedByIsAllBaseline(t *testing.T) {
	claims := gpuClaims(t)
	result, err := NewImplementation().AppraiseClaims(claims, []*comid.ValueTriple{goldenFrom(t, claims, 4, 5, 7)})
	require.NoError(t, err)
	rv := (*result.Submods[Descriptor.Name].VeraisonPolicyClaims)["reference-values"].(map[string]any)
	prov := rv["provenance"].(map[string]any)
	assert.Equal(t, map[string]any{"vendor-backed": 0, "baseline": 2}, prov["executables"])
	assert.Empty(t, prov["vendors"])
}
