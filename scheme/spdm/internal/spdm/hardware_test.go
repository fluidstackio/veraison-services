// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These fixtures are real responses from an NVIDIA GB110 eRoT, captured from
// wdl101-b300-mach2 on 2026-09-09. They matter because every other test in this
// package checks the parser against a responder we wrote ourselves, which cannot
// catch a shared misreading of the specification. Hardware can.

func hardware(t *testing.T, name string) []byte {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", "hardware", name))
	require.NoError(t, err)
	return blob
}

func hardwareChain(t *testing.T) [][]byte {
	t.Helper()
	rest := hardware(t, "hgx-irot-gpu0-chain.pem")
	var chain [][]byte
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		chain = append(chain, block.Bytes)
	}
	require.Len(t, chain, 5)
	return chain
}

// hardwareRoot anchors the chain on its own last certificate. That is circular
// as a trust decision and fine as a test: what is under test is chain building,
// not provenance. See projects/fsattest/trust/README.md.
func hardwareRoot(t *testing.T) *x509.CertPool {
	t.Helper()
	chain := hardwareChain(t)
	root, err := x509.ParseCertificate(chain[len(chain)-1])
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool
}

func TestHardwarePayload(t *testing.T) {
	alg, err := ResolveAlgorithm("TPM_ALG_ECDSA_ECC_NIST_P384", "TPM_ALG_SHA_384")
	require.NoError(t, err)

	t.Run("the all-blocks response decomposes as one exchange", func(t *testing.T) {
		p, err := ParsePayload(hardware(t, "hgx-irot-gpu0-allblocks.bin"), alg.SigLen)
		require.NoError(t, err)

		assert.True(t, p.RequestPrepended, "the responder returns its request")
		assert.Empty(t, p.Prior, "no prior exchanges, so nothing hidden from the transcript")
		assert.Equal(t, V11, p.Final.Version)
		assert.Len(t, p.Final.Blocks, 52)
		assert.Len(t, p.Final.Record, 1842)
		assert.Len(t, p.RequestNonce, NonceSize)
		assert.Empty(t, p.Final.OpaqueData)
	})

	t.Run("the real signature verifies over the supplied transcript", func(t *testing.T) {
		res, err := Verify(Input{
			Response:         hardware(t, "hgx-irot-gpu0-allblocks.bin"),
			CertChain:        hardwareChain(t),
			TrustAnchors:     hardwareRoot(t),
			SigningAlgorithm: "TPM_ALG_ECDSA_ECC_NIST_P384",
			HashingAlgorithm: "TPM_ALG_SHA_384",
			// The nonce this payload answers, which is not one we hold here.
			Nonce:     nil,
			Operation: OperationAllBlocks,
		})
		require.NoError(t, err)
		assert.Equal(t, OutcomeVerified, res.Outcome, res.Reason)
		assert.True(t, res.ChainVerified)
		assert.Equal(t, 52, res.Blocks)
	})

	t.Run("a flipped byte in the real payload fails", func(t *testing.T) {
		blob := hardware(t, "hgx-irot-gpu0-allblocks.bin")
		tampered := make([]byte, len(blob))
		copy(tampered, blob)
		tampered[100] ^= 0x01

		res, err := Verify(Input{
			Response:         tampered,
			CertChain:        hardwareChain(t),
			TrustAnchors:     hardwareRoot(t),
			SigningAlgorithm: "TPM_ALG_ECDSA_ECC_NIST_P384",
			HashingAlgorithm: "TPM_ALG_SHA_384",
			Operation:        OperationAllBlocks,
		})
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, res.Outcome)
	})

	t.Run("a payload answering a different request is detectable", func(t *testing.T) {
		// This one came off the same latch but answers measurement index 26,
		// a request this tool never makes. It is the shape of another party's
		// result being handed back, and the nonce is what catches it.
		p, err := ParsePayload(hardware(t, "hgx-irot-gpu0-foreign-request.bin"), alg.SigLen)
		require.NoError(t, err)

		require.Len(t, p.Final.Blocks, 1)
		assert.Equal(t, 26, p.Final.Blocks[0].Index)
		assert.False(t, p.Final.Blocks[0].IsDigest(), "DMTF type 0x82 is a raw bit stream")

		ours := make([]byte, NonceSize)
		assert.Equal(t, NonceBindingSubstituted, ClassifyNonce(ours, p.RequestNonce),
			"a payload answering someone else's request must never classify as bound")
	})

	t.Run("the chain reaches its root and rejects an unrelated one", func(t *testing.T) {
		chain := hardwareChain(t)

		leaf, err := verifyChain(chain, hardwareRoot(t), time.Now())
		require.NoError(t, err)
		assert.Contains(t, leaf.Subject.CommonName, "GB110")

		_, err = verifyChain(chain, x509.NewCertPool(), time.Now())
		assert.Error(t, err)
	})
}
