// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import "fmt"

// Payload is a SignedMeasurements blob decomposed into the SPDM messages it
// carries.
//
// Some responders return only the final MEASUREMENTS response, in which case the
// request half of the transcript has to be rebuilt from the parameters the
// collector sent. Others return the messages of the exchange, request bytes
// included. The second case is strictly better: the transcript is then given
// rather than inferred, so neither the request encoding nor the responder's
// session history has to be guessed.
type Payload struct {
	// Prior holds complete exchanges that preceded the final one, in order.
	Prior []Exchange
	// FinalRequest is the GET_MEASUREMENTS request for the signed response. It
	// is taken from the payload when present and must otherwise be rebuilt.
	FinalRequest []byte
	// Final is the signed MEASUREMENTS response.
	Final *Measurements
	// RequestPrepended records whether the request bytes came from the responder
	// rather than from reconstruction. It belongs in the appraisal output: it is
	// the difference between verifying a transcript and verifying a guess at one.
	RequestPrepended bool
	// RequestNonce is the requester nonce inside FinalRequest.
	//
	// This, not the response nonce, is where a caller-supplied nonce would
	// appear. DSP0274 gives the MEASUREMENTS response the *responder's* own
	// nonce, so comparing a sent nonce against the response is meaningless: the
	// two are different values by design, on every device.
	RequestNonce []byte
}

// requestLen returns the on-wire length of a GET_MEASUREMENTS request.
//
// The nonce and SlotIDParam are only present when a signature was requested,
// which Param1 bit 0 records, so the length is not fixed.
//
// SlotIDParam was added in SPDM 1.1: a signed 1.0 request ends at the nonce and
// is one byte shorter. Assuming the 1.1 layout put the parse one byte past the
// start of the response on the Intel Xeon S3M sockets, which answer at 1.0, and
// the version byte read there as a RequestResponseCode of 0x00.
func requestLen(buf []byte) (int, error) {
	if len(buf) < headerSize {
		return 0, fmt.Errorf("%w: truncated GET_MEASUREMENTS header", ErrMalformed)
	}
	if buf[2]&attrSignatureRequested == 0 {
		return headerSize, nil
	}
	n := headerSize + NonceSize
	if Version(buf[0]) >= V11 {
		n++ // SlotIDParam
	}
	return n, nil
}

// responseLen returns the length of a MEASUREMENTS response excluding its
// signature, which is only present on the last response of an exchange.
func responseLen(buf []byte) (int, error) {
	off := headerSize
	if err := needs(buf, off, 1+recordLengthSize, "NumberOfBlocks"); err != nil {
		return 0, err
	}
	off++
	recordLen := int(buf[off]) | int(buf[off+1])<<8 | int(buf[off+2])<<16
	off += recordLengthSize

	if err := needs(buf, off, recordLen+NonceSize+opaqueLengthSize, "MeasurementRecord"); err != nil {
		return 0, err
	}
	off += recordLen + NonceSize
	opaqueLen := int(buf[off]) | int(buf[off+1])<<8
	off += opaqueLengthSize

	if err := needs(buf, off, opaqueLen, "OpaqueData"); err != nil {
		return 0, err
	}
	return off + opaqueLen, nil
}

// ParsePayload decomposes a SignedMeasurements blob.
//
// It accepts both shapes: a bare MEASUREMENTS response, and a sequence of
// GET_MEASUREMENTS requests and MEASUREMENTS responses ending in the signed one.
// The signature length has to be supplied because the wire format does not carry
// it; it is implied by the negotiated algorithm, which Redfish reports out of
// band.
func ParsePayload(buf []byte, sigLen int) (*Payload, error) {
	if sigLen <= 0 {
		return nil, fmt.Errorf("%w: signature length %d is not usable", ErrMalformed, sigLen)
	}
	if len(buf) < headerSize {
		return nil, fmt.Errorf("%w: %d bytes is shorter than a message header", ErrMalformed, len(buf))
	}

	// A bare response is the common case and needs no walking.
	if buf[1] == codeMeasurements {
		final, err := ParseMeasurements(buf, sigLen)
		if err != nil {
			return nil, err
		}
		return &Payload{Final: final}, nil
	}
	if buf[1] != codeGetMeasurements {
		return nil, fmt.Errorf("%w: leading RequestResponseCode 0x%02X is neither GET_MEASUREMENTS nor MEASUREMENTS",
			ErrMalformed, buf[1])
	}

	p := &Payload{RequestPrepended: true}
	var (
		pendingRequest []byte
		pendingNonce   []byte
	)

	for off := 0; off < len(buf); {
		switch code := buf[off+1]; code {
		case codeGetMeasurements:
			n, err := requestLen(buf[off:])
			if err != nil {
				return nil, err
			}
			if err := needs(buf, off, n, "GET_MEASUREMENTS"); err != nil {
				return nil, err
			}
			if pendingRequest != nil {
				return nil, fmt.Errorf("%w: two GET_MEASUREMENTS requests with no response between them",
					ErrMalformed)
			}
			pendingRequest = buf[off : off+n]
			if n >= headerSize+NonceSize {
				pendingNonce = buf[off+headerSize : off+headerSize+NonceSize]
			}
			off += n

		case codeMeasurements:
			if pendingRequest == nil {
				return nil, fmt.Errorf("%w: MEASUREMENTS response with no preceding request", ErrMalformed)
			}
			unsigned, err := responseLen(buf[off:])
			if err != nil {
				return nil, err
			}
			// The signed response is the one whose signature runs to the end of
			// the payload. Anything else is an intermediate exchange that the
			// transcript covers but that carries no signature of its own.
			if off+unsigned+sigLen == len(buf) {
				final, err := ParseMeasurements(buf[off:], sigLen)
				if err != nil {
					return nil, err
				}
				p.FinalRequest = pendingRequest
				p.RequestNonce = pendingNonce
				p.Final = final
				return p, nil
			}
			p.Prior = append(p.Prior, Exchange{
				Request:  pendingRequest,
				Response: buf[off : off+unsigned],
			})
			pendingRequest, pendingNonce = nil, nil
			off += unsigned

		default:
			return nil, fmt.Errorf("%w: unexpected RequestResponseCode 0x%02X at offset %d",
				ErrMalformed, code, off)
		}

		if off+headerSize > len(buf) {
			return nil, fmt.Errorf("%w: payload ends without a signed MEASUREMENTS response", ErrMalformed)
		}
	}
	return nil, fmt.Errorf("%w: payload ends without a signed MEASUREMENTS response", ErrMalformed)
}

// Transcript returns the L1/L2 bytes the signature covers.
func (p *Payload) Transcript() []byte {
	return BuildTranscript(p.Prior, p.FinalRequest, p.Final)
}
