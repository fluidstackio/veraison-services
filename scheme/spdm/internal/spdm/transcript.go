// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

// Measurement operation values carried in GET_MEASUREMENTS Param2.
const (
	// OperationAllBlocks asks the responder for every measurement block.
	OperationAllBlocks uint8 = 0xFF
	// OperationBlockCount asks only how many blocks exist.
	OperationBlockCount uint8 = 0x00
)

// attrSignatureRequested is bit 0 of GET_MEASUREMENTS Param1.
const attrSignatureRequested uint8 = 0x01

// Exchange is one GET_MEASUREMENTS request and its MEASUREMENTS response, as
// they appeared on the wire.
type Exchange struct {
	Request  []byte
	Response []byte
}

// BuildGetMeasurements reproduces the request bytes for an exchange.
//
// The collector authored these parameters, so it can rebuild the request the BMC
// sent — but only if the BMC sent exactly this request. That assumption is one
// of the things the validation gate exists to test.
func BuildGetMeasurements(v Version, operation, slotID uint8, nonce []byte) []byte {
	signed := len(nonce) > 0

	var attrs uint8
	if signed {
		attrs = attrSignatureRequested
	}

	req := make([]byte, 0, headerSize+NonceSize+1)
	req = append(req, byte(v), codeGetMeasurements, attrs, operation)
	if signed {
		req = append(req, nonce...)
		// SlotIDParam arrived in SPDM 1.1; a 1.0 signed request ends at the nonce.
		if v >= V11 {
			req = append(req, slotID)
		}
	}
	return req
}

// BuildTranscript assembles L1/L2 for SPDM 1.0 and 1.1: every GET_MEASUREMENTS
// request and MEASUREMENTS response in the session, in order, with the final
// response contributing everything the signature covers but not the signature
// itself.
//
// prior carries exchanges the BMC performed before ours on the same SPDM
// context. Passing none asserts that the responder used a fresh context for this
// action. That assertion is not verifiable from the response, so a caller that
// cannot establish it should treat a verification failure as inconclusive rather
// than as a bad signature.
func BuildTranscript(prior []Exchange, finalRequest []byte, final *Measurements) []byte {
	size := len(finalRequest) + len(final.SignedPrefix)
	for _, e := range prior {
		size += len(e.Request) + len(e.Response)
	}

	transcript := make([]byte, 0, size)
	for _, e := range prior {
		transcript = append(transcript, e.Request...)
		transcript = append(transcript, e.Response...)
	}
	transcript = append(transcript, finalRequest...)
	return append(transcript, final.SignedPrefix...)
}
