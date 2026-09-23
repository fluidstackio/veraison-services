// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"bytes"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/veraison/services/scheme/spdm/internal/spdmtest"
)

func input(r *spdmtest.Responder, response, nonce []byte) Input {
	return Input{
		Response:         response,
		CertChain:        r.Chain,
		TrustAnchors:     r.Roots,
		SigningAlgorithm: algSigning,
		HashingAlgorithm: algHashing,
		Nonce:            nonce,
		Operation:        OperationAllBlocks,
	}
}

func TestParseMeasurements(t *testing.T) {
	r := spdmtest.NewResponder(t)
	alg, err := ResolveAlgorithm(algSigning, algHashing)
	require.NoError(t, err)

	t.Run("parses blocks and sizes", func(t *testing.T) {
		blob := r.Build(t, spdmtest.Options{})

		m, err := ParseMeasurements(blob, alg.SigLen)
		require.NoError(t, err)

		assert.Equal(t, V11, m.Version)
		require.Len(t, m.Blocks, 3)
		assert.Equal(t, 1, m.Blocks[0].Index)
		assert.Len(t, m.Blocks[0].Value, 48)
		assert.True(t, m.Blocks[0].IsDigest())
		assert.Equal(t, []byte("raw-config-bits"), m.Blocks[2].Value)
		assert.False(t, m.Blocks[2].IsDigest(), "value type bit 7 marks a raw bit stream")
		assert.Len(t, m.Nonce, NonceSize)
		assert.Len(t, m.Signature, alg.SigLen)
	})

	t.Run("the signed prefix excludes the signature", func(t *testing.T) {
		blob := r.Build(t, spdmtest.Options{})

		m, err := ParseMeasurements(blob, alg.SigLen)
		require.NoError(t, err)
		assert.Len(t, m.SignedPrefix, len(blob)-alg.SigLen)
		assert.True(t, bytes.Equal(blob[:len(blob)-alg.SigLen], m.SignedPrefix))
	})

	t.Run("truncated and inconsistent blobs error rather than returning partials", func(t *testing.T) {
		good := r.Build(t, spdmtest.Options{})

		cases := map[string][]byte{
			"empty":                    {},
			"header only":              good[:headerSize],
			"cut mid-record":           good[:headerSize+8],
			"cut before the signature": good[:len(good)-alg.SigLen-1],
			"one byte short":           good[:len(good)-1],
		}
		for name, blob := range cases {
			t.Run(name, func(t *testing.T) {
				m, err := ParseMeasurements(blob, alg.SigLen)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrMalformed)
				assert.Nil(t, m, "a failed parse must not hand back a partial structure")
			})
		}
	})

	t.Run("trailing bytes are rejected", func(t *testing.T) {
		blob := append(r.Build(t, spdmtest.Options{}), 0x00)

		_, err := ParseMeasurements(blob, alg.SigLen)
		assert.ErrorIs(t, err, ErrMalformed)
	})

	t.Run("a non-MEASUREMENTS response code is rejected", func(t *testing.T) {
		blob := r.Build(t, spdmtest.Options{})
		blob[1] = 0x63

		_, err := ParseMeasurements(blob, alg.SigLen)
		assert.ErrorIs(t, err, ErrMalformed)
	})
}

func TestVerify(t *testing.T) {
	r := spdmtest.NewResponder(t)

	t.Run("a known-good response verifies", func(t *testing.T) {
		nonce := zeroNonce()
		blob := r.Build(t, spdmtest.Options{Nonce: nonce})

		res, err := Verify(input(r, blob, nonce))
		require.NoError(t, err)
		assert.Equal(t, OutcomeVerified, res.Outcome, res.Reason)
		assert.True(t, res.ChainVerified)
		assert.Equal(t, 3, res.Blocks)
		// A bare response carries no request bytes, so there is nowhere the
		// caller's nonce could appear. The response nonce is the responder's own
		// and is not an echo, so freshness is simply unprovable here.
		assert.Equal(t, NonceBindingUnverifiable, res.NonceBinding)
		assert.False(t, res.NonceMatched)
	})

	t.Run("a single flipped measurement byte fails, and is not called unverifiable", func(t *testing.T) {
		nonce := zeroNonce()
		blob := r.Build(t, spdmtest.Options{Nonce: nonce, CorruptRecord: true})

		res, err := Verify(input(r, blob, nonce))
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, res.Outcome,
			"a bad signature is a failure, not an absence of evidence")
	})

	t.Run("a signature from the wrong key fails", func(t *testing.T) {
		nonce := zeroNonce()
		blob := r.Build(t, spdmtest.Options{Nonce: nonce, WrongKey: true})

		res, err := Verify(input(r, blob, nonce))
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, res.Outcome)
	})

	t.Run("1.2 and later are unverifiable and never verified", func(t *testing.T) {
		for _, v := range []Version{V12, V13} {
			nonce := zeroNonce()
			// Every other input is well formed: the responder signs a correct
			// transcript. Only the reported version differs.
			blob := r.Build(t, spdmtest.Options{VersionByte: byte(v), Nonce: nonce})

			res, err := Verify(input(r, blob, nonce))
			require.NoError(t, err)
			assert.Equal(t, OutcomeUnverifiableTranscript, res.Outcome, "SPDM %s", v)
			assert.Contains(t, res.Reason, "VCA")
		}
	})

	t.Run("the response nonce is never compared against the one sent", func(t *testing.T) {
		sent := bytes.Repeat([]byte{0xAA}, NonceSize)
		responderNonce := bytes.Repeat([]byte{0xBB}, NonceSize)
		blob := r.Build(t, spdmtest.Options{Nonce: responderNonce})

		// DSP0274 gives the MEASUREMENTS response the responder's own nonce, so
		// these two values differing is normal and must not surface as a nonce
		// error. Binding is unprovable because a bare response carries no request
		// bytes to look in.
		res, err := Verify(input(r, blob, sent))
		require.NoError(t, err, "differing nonces must not raise a nonce error")
		var mismatch *ErrNonceMismatch
		assert.NotErrorAs(t, err, &mismatch)
		assert.Equal(t, NonceBindingUnverifiable, res.NonceBinding)

		// The signature does not verify here, but for an unrelated reason worth
		// naming: with no request bytes in the payload the transcript has to be
		// rebuilt from the nonce the caller says it sent, and this fixture signs
		// over a different one. It is the reconstruction that fails, not a
		// freshness check.
		assert.Equal(t, OutcomeFailed, res.Outcome)
	})

	t.Run("the chain must reach the supplied anchor", func(t *testing.T) {
		nonce := zeroNonce()
		in := input(r, r.Build(t, spdmtest.Options{Nonce: nonce}), nonce)
		in.TrustAnchors = r.UnrelatedRoots

		res, err := Verify(in)
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, res.Outcome)
		assert.False(t, res.ChainVerified)
		assert.Contains(t, res.Reason, "trust anchor")
	})

	t.Run("no anchors means the chain is not claimed as verified", func(t *testing.T) {
		nonce := zeroNonce()
		in := input(r, r.Build(t, spdmtest.Options{Nonce: nonce}), nonce)
		in.TrustAnchors = nil

		res, err := Verify(in)
		require.NoError(t, err)
		assert.Equal(t, OutcomeVerified, res.Outcome, "the signature still checks out")
		assert.False(t, res.ChainVerified, "but nothing anchored it")
	})

	t.Run("an empty chain fails", func(t *testing.T) {
		nonce := zeroNonce()
		in := input(r, r.Build(t, spdmtest.Options{Nonce: nonce}), nonce)
		in.CertChain = nil

		res, err := Verify(in)
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, res.Outcome)
	})

	t.Run("an unsupported algorithm is an error, not a guess", func(t *testing.T) {
		in := input(r, r.Build(t, spdmtest.Options{}), nil)
		in.SigningAlgorithm = "TPM_ALG_RSASSA_4096"
		in.HashingAlgorithm = "TPM_ALG_SHA3_512"

		_, err := Verify(in)
		var unsupported *ErrUnsupportedAlgorithm
		assert.ErrorAs(t, err, &unsupported)
	})

	t.Run("prior exchanges on the same context change the transcript", func(t *testing.T) {
		nonce := zeroNonce()
		prior := []spdmtest.Exchange{{Request: []byte("earlier-request"), Response: []byte("earlier-response")}}
		blob := r.Build(t, spdmtest.Options{Nonce: nonce, Prior: prior})

		withoutPrior, err := Verify(input(r, blob, nonce))
		require.NoError(t, err)
		assert.Equal(t, OutcomeFailed, withoutPrior.Outcome,
			"a responder reusing a context cannot be verified from our exchange alone")

		in := input(r, blob, nonce)
		in.Prior = []Exchange{{Request: prior[0].Request, Response: prior[0].Response}}
		withPrior, err := Verify(in)
		require.NoError(t, err)
		assert.Equal(t, OutcomeVerified, withPrior.Outcome, withPrior.Reason)
	})
}

func TestResolveAlgorithm(t *testing.T) {
	cases := []struct {
		signing, hashing string
		want             string
		wantLen          int
	}{
		{algSigning, algHashing, "ECDSA_P384_SHA384", 96},
		{"ECDSA-P384", "SHA-512", "ECDSA_P384_SHA512", 96},
		{"TPM_ALG_ECDSA_ECC_NIST_P256", "TPM_ALG_SHA_256", "ECDSA_P256_SHA256", 64},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			alg, err := ResolveAlgorithm(tc.signing, tc.hashing)
			require.NoError(t, err)
			assert.Equal(t, tc.want, alg.Name)
			assert.Equal(t, tc.wantLen, alg.SigLen)
		})
	}
}

func TestVersion(t *testing.T) {
	t.Run("only 1.0 and 1.1 have reconstructible transcripts", func(t *testing.T) {
		assert.True(t, V10.TranscriptReconstructible())
		assert.True(t, V11.TranscriptReconstructible())
		assert.False(t, V12.TranscriptReconstructible())
		assert.False(t, V13.TranscriptReconstructible())
	})

	t.Run("parses the dotted Redfish form", func(t *testing.T) {
		v, err := ParseVersion("1.1.0")
		require.NoError(t, err)
		assert.Equal(t, V11, v)
		assert.Equal(t, "1.1", v.String())
	})
}

func TestVerifyChain(t *testing.T) {
	t.Run("a garbage DER blob is reported as a parse failure", func(t *testing.T) {
		_, err := verifyChain([][]byte{[]byte("not der")}, x509.NewCertPool(), time.Time{})
		require.Error(t, err)
	})

	// SPDM defines the chain root-first and the ConnectX NICs send it that way,
	// while the NVIDIA GPU and ERoT targets send the exact reverse. Picking
	// certs[0] verified NIC measurements against the root CA's key, which
	// presented as a signature failure rather than as a chain-order problem.
	t.Run("the leaf is found whichever end of the chain it sits at", func(t *testing.T) {
		r := spdmtest.NewResponder(t)

		leafFirst, err := verifyChain(r.Chain, r.Roots, time.Time{})
		require.NoError(t, err)

		reversed := make([][]byte, len(r.Chain))
		for i, der := range r.Chain {
			reversed[len(r.Chain)-1-i] = der
		}
		rootFirst, err := verifyChain(reversed, r.Roots, time.Time{})
		require.NoError(t, err)

		assert.Equal(t, leafFirst.Subject.CommonName, rootFirst.Subject.CommonName,
			"the same certificate must be chosen regardless of chain order")
		assert.False(t, rootFirst.IsCA, "a CA certificate was chosen as the leaf")
	})
}

// The ConnectX IRoT targets report SHA-512 in Redfish's HashingAlgorithm while
// signing with SHA-384 — the MeasurementHashAlgo/BaseHashAlgo split, which
// Redfish flattens into one field. The declared digest therefore cannot be the
// only one tried.
func TestAlternateDigests(t *testing.T) {
	t.Run("P384 offers the other digest of the same signature width", func(t *testing.T) {
		declared, err := ResolveAlgorithm("TPM_ALG_ECDSA_ECC_NIST_P384", "TPM_ALG_SHA_512")
		require.NoError(t, err)
		require.Equal(t, "ECDSA_P384_SHA512", declared.Name)

		alts := alternateDigests(declared)
		require.NotEmpty(t, alts, "no alternative digest offered for P-384")

		var names []string
		for _, a := range alts {
			assert.Equal(t, declared.SigLen, a.SigLen,
				"an alternative must not change the signature width")
			assert.NotEqual(t, declared.Hash, a.Hash)
			names = append(names, a.Name)
		}
		assert.Contains(t, names, "ECDSA_P384_SHA384")
	})

	t.Run("alternatives never cross a signature width", func(t *testing.T) {
		p256, err := ResolveAlgorithm("ECDSA-P256", "SHA256")
		require.NoError(t, err)
		for _, a := range alternateDigests(p256) {
			assert.Equal(t, p256.SigLen, a.SigLen)
		}
	})
}

// SlotIDParam arrived in SPDM 1.1. Treating a signed 1.0 request as 1.1-sized
// put the parse one byte past the start of the response on the Intel Xeon S3M
// sockets, and the version byte read there as a RequestResponseCode of 0x00.
func TestRequestLenAcrossVersions(t *testing.T) {
	signed := func(v Version) []byte {
		return append([]byte{byte(v), codeGetMeasurements, attrSignatureRequested, OperationAllBlocks},
			make([]byte, NonceSize+1)...)
	}

	t.Run("a signed 1.0 request ends at the nonce", func(t *testing.T) {
		n, err := requestLen(signed(V10))
		require.NoError(t, err)
		assert.Equal(t, headerSize+NonceSize, n)
	})

	t.Run("a signed 1.1 request carries SlotIDParam", func(t *testing.T) {
		n, err := requestLen(signed(V11))
		require.NoError(t, err)
		assert.Equal(t, headerSize+NonceSize+1, n)
	})

	t.Run("an unsigned request is the header alone at either version", func(t *testing.T) {
		for _, v := range []Version{V10, V11} {
			n, err := requestLen([]byte{byte(v), codeGetMeasurements, 0x00, OperationBlockCount})
			require.NoError(t, err)
			assert.Equal(t, headerSize, n)
		}
	})

	t.Run("the built request round-trips through the parser", func(t *testing.T) {
		for _, v := range []Version{V10, V11} {
			req := BuildGetMeasurements(v, OperationAllBlocks, 0, make([]byte, NonceSize))
			n, err := requestLen(req)
			require.NoError(t, err)
			assert.Equal(t, len(req), n, "SPDM %s request length disagrees with the parser", v)
		}
	})
}
