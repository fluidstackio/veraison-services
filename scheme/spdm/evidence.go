// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	wire "github.com/veraison/services/scheme/spdm/internal/spdm"
)

// SchemaVersion is the fsattest evidence bundle schema this scheme reads.
const SchemaVersion = "1"

var ErrSchema = errors.New("evidence bundle schema error")

// TransportTrust records how the collector authenticated the BMC. It has no
// bearing on the signature, which the device produced and the BMC only relays,
// but it is reported so a collection taken with verification disabled is
// visible in the result.
type TransportTrust struct {
	Mode     string `cbor:"1,keyasint" json:"mode"`
	Verified bool   `cbor:"2,keyasint" json:"verified"`
}

// Bundle is one SPDM target's evidence, as fsattest collects it over Redfish.
//
// The CBOR keys are fsattest's schema v1 (internal/evidence/bundle.go) and must
// not be renumbered: the collector encodes, this decodes. Fields this scheme
// does not use are omitted, which CBOR decoding tolerates.
type Bundle struct {
	SchemaVersion string `cbor:"1,keyasint" json:"schema_version"`
	NodeID        string `cbor:"3,keyasint,omitempty" json:"node_id,omitempty"`
	TargetID      string `cbor:"4,keyasint" json:"target_id"`
	CollectedAt   string `cbor:"5,keyasint" json:"collected_at"`
	SPDMVersion   string `cbor:"6,keyasint" json:"spdm_version"`
	HashAlg       string `cbor:"7,keyasint" json:"hash_alg"`
	SigAlg        string `cbor:"8,keyasint" json:"sig_alg"`

	// Nonce is what the collector says it sent. It is unsigned metadata and is
	// never used for freshness: the session nonce is, checked against the
	// transcript.
	Nonce []byte `cbor:"9,keyasint" json:"nonce"`

	SlotID             int   `cbor:"10,keyasint" json:"slot_id"`
	MeasurementIndices []int `cbor:"11,keyasint,omitempty" json:"measurement_indices,omitempty"`

	SignedMeasurements []byte   `cbor:"12,keyasint" json:"signed_measurements"`
	CertChain          [][]byte `cbor:"13,keyasint" json:"cert_chain"`

	TransportTrust TransportTrust `cbor:"15,keyasint" json:"transport_trust"`
	PrimingPayload []byte         `cbor:"17,keyasint,omitempty" json:"priming_payload,omitempty"`
}

func decodeBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := cbor.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%w: decoding CBOR: %v", ErrSchema, err)
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

func (b *Bundle) validate() error {
	var missing []string
	if b.SchemaVersion == "" {
		missing = append(missing, "schema_version")
	}
	if b.TargetID == "" {
		missing = append(missing, "target_id")
	}
	if len(b.SignedMeasurements) == 0 {
		missing = append(missing, "signed_measurements")
	}
	if b.SigAlg == "" {
		missing = append(missing, "sig_alg")
	}
	if b.HashAlg == "" {
		missing = append(missing, "hash_alg")
	}
	if len(b.CertChain) == 0 {
		missing = append(missing, "cert_chain")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %v", ErrSchema, missing)
	}
	if b.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema_version %q, this scheme reads %q",
			ErrSchema, b.SchemaVersion, SchemaVersion)
	}
	if b.SlotID < 0 || b.SlotID > 0x0F {
		return fmt.Errorf("%w: slot_id %d out of range", ErrSchema, b.SlotID)
	}
	return nil
}

// operation is the GET_MEASUREMENTS Param2 the collector requested, which the
// transcript has to be rebuilt with when the responder returned no request
// bytes. The same rule as fsattest's own appraisal.
func (b *Bundle) operation() (uint8, error) {
	if len(b.MeasurementIndices) != 1 {
		return wire.OperationAllBlocks, nil
	}
	idx := b.MeasurementIndices[0]
	if idx < 0 || idx > 0xFF {
		return 0, fmt.Errorf("%w: measurement index %d out of range", ErrSchema, idx)
	}
	return uint8(idx), nil //nolint:gosec // bounds checked above
}
