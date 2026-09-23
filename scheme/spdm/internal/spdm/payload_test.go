// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/veraison/services/scheme/spdm/internal/spdmtest"
)

const (
	algSigning = "TPM_ALG_ECDSA_ECC_NIST_P384"
	algHashing = "TPM_ALG_SHA_384"
)

func zeroNonce() []byte { return make([]byte, NonceSize) }

// prependRequest wraps a bare response in the shape observed on a Dell iDRAC
// fronting NVIDIA HGX eRoTs: the payload opens with the GET_MEASUREMENTS
// request rather than the MEASUREMENTS response.
func prependRequest(version byte, operation, slotID uint8, nonce, response []byte) []byte {
	req := spdmtest.GetMeasurementsRequest(version, operation, slotID, nonce)
	return append(append([]byte{}, req...), response...)
}

func TestParsePayload(t *testing.T) {
	r := spdmtest.NewResponder(t)
	alg, err := ResolveAlgorithm(algSigning, algHashing)
	require.NoError(t, err)

	t.Run("a bare response needs no request bytes", func(t *testing.T) {
		blob := r.Build(t, spdmtest.Options{})

		p, err := ParsePayload(blob, alg.SigLen)
		require.NoError(t, err)
		assert.False(t, p.RequestPrepended)
		assert.Empty(t, p.Prior)
		assert.Empty(t, p.FinalRequest)
		require.NotNil(t, p.Final)
		assert.Len(t, p.Final.Blocks, 3)
	})

	t.Run("a prepended request is taken from the payload", func(t *testing.T) {
		nonce := zeroNonce()
		response := r.Build(t, spdmtest.Options{Nonce: nonce})
		blob := prependRequest(byte(V11), OperationAllBlocks, 0, nonce, response)

		p, err := ParsePayload(blob, alg.SigLen)
		require.NoError(t, err)
		assert.True(t, p.RequestPrepended)
		assert.Empty(t, p.Prior)
		assert.Len(t, p.FinalRequest, headerSize+NonceSize+1,
			"a signed request carries the nonce and SlotIDParam")
		assert.Equal(t, byte(codeGetMeasurements), p.FinalRequest[1])
		require.NotNil(t, p.Final)
	})

	t.Run("the transcript is the payload itself when the request is present", func(t *testing.T) {
		nonce := zeroNonce()
		response := r.Build(t, spdmtest.Options{Nonce: nonce})
		blob := prependRequest(byte(V11), OperationAllBlocks, 0, nonce, response)

		p, err := ParsePayload(blob, alg.SigLen)
		require.NoError(t, err)
		assert.Equal(t, blob[:len(blob)-alg.SigLen], p.Transcript(),
			"L1/L2 is every byte the responder sent bar the signature")
	})

	t.Run("a leading code that is neither request nor response is rejected", func(t *testing.T) {
		blob := r.Build(t, spdmtest.Options{})
		blob[1] = 0x63

		_, err := ParsePayload(blob, alg.SigLen)
		assert.ErrorIs(t, err, ErrMalformed)
	})

	t.Run("a request with no response is rejected", func(t *testing.T) {
		nonce := zeroNonce()
		onlyRequest := spdmtest.GetMeasurementsRequest(byte(V11), OperationAllBlocks, 0, nonce)

		_, err := ParsePayload(onlyRequest, alg.SigLen)
		assert.ErrorIs(t, err, ErrMalformed)
	})

	t.Run("two requests with no response between them are rejected", func(t *testing.T) {
		nonce := zeroNonce()
		req := spdmtest.GetMeasurementsRequest(byte(V11), OperationAllBlocks, 0, nonce)
		blob := append(append([]byte{}, req...), req...)
		blob = append(blob, r.Build(t, spdmtest.Options{Nonce: nonce})...)

		_, err := ParsePayload(blob, alg.SigLen)
		assert.ErrorIs(t, err, ErrMalformed)
	})
}

func TestVerifyWithPrependedRequest(t *testing.T) {
	r := spdmtest.NewResponder(t)

	t.Run("a payload carrying its own request verifies without reconstruction", func(t *testing.T) {
		nonce := zeroNonce()
		response := r.Build(t, spdmtest.Options{Nonce: nonce})
		blob := prependRequest(byte(V11), OperationAllBlocks, 0, nonce, response)

		// Operation and SlotID are deliberately wrong. If verification still
		// succeeds, the transcript came from the payload rather than from these.
		in := input(r, blob, nonce)
		in.Operation = 0x01
		in.SlotID = 7

		res, err := Verify(in)
		require.NoError(t, err)
		assert.Equal(t, OutcomeVerified, res.Outcome, res.Reason)
		assert.True(t, res.RequestPrepended)
		assert.Equal(t, 0, res.PriorExchanges)
	})

	t.Run("a tampered measurement still fails when the request is prepended", func(t *testing.T) {
		nonce := zeroNonce()
		response := r.Build(t, spdmtest.Options{Nonce: nonce, CorruptRecord: true})
		blob := prependRequest(byte(V11), OperationAllBlocks, 0, nonce, response)

		res, err := Verify(input(r, blob, nonce))
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, res.Outcome)
	})

	t.Run("the nonce is bound when the transcript carries the one we sent", func(t *testing.T) {
		sent := zeroNonce()
		response := r.Build(t, spdmtest.Options{Nonce: sent})
		blob := prependRequest(byte(V11), OperationAllBlocks, 0, sent, response)

		res, err := Verify(input(r, blob, sent))
		require.NoError(t, err)
		assert.Equal(t, NonceBindingVerifier, res.NonceBinding)
		assert.True(t, res.NonceMatched)
	})

	t.Run("a substituted requester nonce is recorded, not treated as a bad device", func(t *testing.T) {
		// The shape observed on a Dell iDRAC: it ignores the Redfish Nonce
		// parameter and puts its own into the SPDM request it makes. The
		// measurements are genuine and the signature valid; what is absent is
		// verifier-controlled freshness, and that has to be visible rather than
		// fatal.
		ownNonce := bytes.Repeat([]byte{0x5A}, NonceSize)
		response := r.Build(t, spdmtest.Options{Nonce: ownNonce})
		blob := prependRequest(byte(V11), OperationAllBlocks, 0, ownNonce, response)

		res, err := Verify(input(r, blob, zeroNonce()))
		require.NoError(t, err)
		assert.Equal(t, OutcomeVerified, res.Outcome, res.Reason)
		assert.Equal(t, NonceBindingSubstituted, res.NonceBinding)
		assert.False(t, res.NonceMatched, "freshness must not be claimed")
	})
}
