// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

// Package spdm appraises DMTF SPDM signed measurements retrieved from a BMC
// over Redfish (ComponentIntegrity.SPDMGetSignedMeasurements), as collected by
// fsattest into an evidence bundle.
//
// What an affirming result means, and does not: the measurements were signed by
// a device whose certificate chains to the provisioned vendor root, over a
// transcript that carries this session's nonce. It says nothing yet about what
// was measured -- the blocks are reported, not compared against reference
// values -- so the executables and configuration claims stay unset.
package spdm

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/veraison/corim/comid"
	"github.com/veraison/ear"
	"github.com/veraison/services/handler"
	"github.com/veraison/services/log"
	"github.com/veraison/services/scheme/common"
	wire "github.com/veraison/services/scheme/spdm/internal/spdm"
	"github.com/veraison/services/vts/appraisal"
	"go.uber.org/zap"
)

// EvidenceMediaType matches fsattest's evidence.MediaType.
const EvidenceMediaType = "application/vnd.fluidstack.spdm-evidence+cbor"

var Descriptor = handler.SchemeDescriptor{
	Name:         "SPDM",
	VersionMajor: 1,
	VersionMinor: 0,
	CorimProfiles: []string{
		ProfileString,
	},
	EvidenceMediaTypes: []string{
		EvidenceMediaType,
	},
}

var (
	ErrNoRoot       = errors.New("certificate chain has no self-signed root")
	ErrRootIdentity = errors.New("root certificate has no organization to identify its vendor")
	ErrSessionNonce = fmt.Errorf("session nonce must be %d bytes, the SPDM requester nonce size", wire.NonceSize)
)

// now is replaced in tests.
var now = time.Now

type Implementation struct {
	logger *zap.SugaredLogger
}

func NewImplementation() *Implementation {
	return &Implementation{logger: log.Named(Descriptor.Name)}
}

// GetTrustAnchorIDs names the vendor root the chain claims to end at. Nothing
// is trusted here: the lookup only decides which provisioned root the chain is
// then verified against, and a chain that merely names a known root fails there.
func (o *Implementation) GetTrustAnchorIDs(
	evidence *appraisal.Evidence,
) ([]*comid.Environment, error) {
	b, err := decodeBundle(evidence.Data)
	if err != nil {
		return nil, handler.BadEvidence(err)
	}

	root, err := chainRoot(b.CertChain)
	if err != nil {
		return nil, handler.BadEvidence(err)
	}
	if len(root.Subject.Organization) == 0 {
		return nil, handler.BadEvidence(ErrRootIdentity)
	}

	return []*comid.Environment{{
		Class: &comid.Class{
			Vendor: &root.Subject.Organization[0],
			Model:  &root.Subject.CommonName,
		},
	}}, nil
}

// ExtractClaims decodes the measurements without trusting them; integrity is
// established by ValidateEvidenceIntegrity, which vts runs before appraisal.
func (o *Implementation) ExtractClaims(
	evidence *appraisal.Evidence,
	trustAnchors []*comid.KeyTriple,
) (map[string]any, error) {
	b, err := decodeBundle(evidence.Data)
	if err != nil {
		return nil, handler.BadEvidence(err)
	}

	alg, err := wire.ResolveAlgorithm(b.SigAlg, b.HashAlg)
	if err != nil {
		return nil, handler.BadEvidence(err)
	}
	payload, err := wire.ParsePayload(b.SignedMeasurements, alg.SigLen)
	if err != nil {
		return nil, handler.BadEvidence(err)
	}
	m := payload.Final

	blocks := make([]any, 0, len(m.Blocks))
	for _, blk := range m.Blocks {
		entry := map[string]any{
			"index":            blk.Index,
			"dmtf-value-type":  int(blk.DMTFValueType),
			"value-is-digest":  blk.IsDigest(),
			"value":            hex.EncodeToString(blk.Value),
			"measurement-spec": int(blk.Specification),
		}
		blocks = append(blocks, entry)
	}

	claims := map[string]any{
		"target-id":           b.TargetID,
		"spdm-version":        m.Version.String(),
		"signature-algorithm": alg.Name,
		"request-in-payload":  payload.RequestPrepended,
		"measurements":        blocks,
		"transport-verified":  b.TransportTrust.Verified,
		"transport-mode":      b.TransportTrust.Mode,
		"collected-at":        b.CollectedAt,
	}
	if b.NodeID != "" {
		claims["node-id"] = b.NodeID
	}
	return claims, nil
}

// ValidateEvidenceIntegrity is the whole trust decision: signature, chain and
// freshness. Anything short of a verified signature over a transcript bound to
// this session's nonce is bad evidence, which vts reports as crypto validation
// failed rather than as an appraisal of the measurements.
func (o *Implementation) ValidateEvidenceIntegrity(
	evidence *appraisal.Evidence,
	trustAnchors []*comid.KeyTriple,
	endorsements []*comid.ValueTriple,
) error {
	anchor, err := trustAnchorCert(trustAnchors)
	if err != nil {
		return handler.BadEvidence(err)
	}

	// The session nonce, never the bundle's: the bundle's is what the collector
	// says it sent, and is not covered by any signature.
	if len(evidence.Nonce) != wire.NonceSize {
		return handler.BadEvidence(ErrSessionNonce)
	}

	b, err := decodeBundle(evidence.Data)
	if err != nil {
		return handler.BadEvidence(err)
	}
	op, err := b.operation()
	if err != nil {
		return handler.BadEvidence(err)
	}

	// Only the provisioned root. A copy of it inside the chain, or any root the
	// chain brings along, contributes nothing to the path.
	anchors := x509.NewCertPool()
	anchors.AddCert(anchor)

	res, err := wire.Verify(wire.Input{
		Response:         b.SignedMeasurements,
		CertChain:        b.CertChain,
		TrustAnchors:     anchors,
		Now:              now(),
		SigningAlgorithm: b.SigAlg,
		HashingAlgorithm: b.HashAlg,
		Nonce:            evidence.Nonce,
		SlotID:           uint8(b.SlotID), //nolint:gosec // validated in decodeBundle
		Operation:        op,
		PrimingPayload:   b.PrimingPayload,
	})
	if err != nil {
		return handler.BadEvidence(err)
	}

	if res.Outcome != wire.OutcomeVerified {
		return handler.BadEvidence("SPDM measurements not verified (%s): %s", res.Outcome, res.Reason)
	}
	if !res.ChainVerified {
		return handler.BadEvidence("responder certificate chain was not verified against the trust anchor")
	}

	// Freshness. With the request in the payload, the transcript is the
	// responder's own and the nonce in it must be ours. Without it, the
	// transcript was rebuilt from our nonce, so a signature that verifies
	// over it already proves the responder answered this session.
	if res.RequestPrepended && res.NonceBinding != wire.NonceBindingVerifier {
		return handler.BadEvidence(
			"signed request does not carry this session's nonce (%s): the payload answers another request",
			res.NonceBinding)
	}

	o.logger.Debugw("SPDM measurements verified",
		"target", b.TargetID, "spdm", res.Version.String(), "algorithm", res.Algorithm,
		"blocks", res.Blocks, "request-in-payload", res.RequestPrepended,
		"prior-exchanges", res.PriorExchanges, "digest-corrected", res.DigestCorrected)
	return nil
}

// AppraiseClaims runs only after integrity validation has passed, so the device
// is genuine and the result fresh. Measurements are not compared against
// anything yet, so no claim is made about them.
func (o *Implementation) AppraiseClaims(
	claims map[string]any,
	endorsements []*comid.ValueTriple,
) (*ear.AttestationResult, error) {
	result := handler.CreateAttestationResult(Descriptor.Name)
	a := result.Submods[Descriptor.Name]

	a.TrustVector.Hardware = ear.GenuineHardwareClaim
	a.UpdateStatusFromTrustVector()
	a.VeraisonAnnotatedEvidence = &claims

	return result, nil
}

func trustAnchorCert(trustAnchors []*comid.KeyTriple) (*x509.Certificate, error) {
	vk, err := common.ExtractOneVerifKey(trustAnchors)
	if err != nil {
		return nil, err
	}
	if vk.Type() != comid.PKIXBase64CertType {
		return nil, fmt.Errorf("trust anchor must be %s, found %s", comid.PKIXBase64CertType, vk.Type())
	}

	der := []byte(vk.String())
	if blk, _ := pem.Decode(der); blk != nil {
		der = blk.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing trust anchor: %w", err)
	}
	return cert, nil
}

// chainRoot finds the self-signed certificate in the chain, whatever its
// position: NVIDIA GPU responders present the chain leaf-first and ConnectX
// root-first, on the same machine.
func chainRoot(chain [][]byte) (*x509.Certificate, error) {
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return cert, nil
		}
	}
	return nil, ErrNoRoot
}
