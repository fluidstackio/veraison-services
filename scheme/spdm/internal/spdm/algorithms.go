// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"crypto"
	_ "crypto/sha256" // registers SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // registers SHA-384 and SHA-512
	"fmt"
	"strings"
)

// Algorithm binds a reported signing algorithm to what verification needs: the
// digest to take over the transcript and the fixed width of the raw r||s
// signature, which the wire format does not carry.
//
// Adding an algorithm is an entry in the table below; no call site changes.
type Algorithm struct {
	Name string
	Hash crypto.Hash
	// SigLen is the total length of the raw signature, twice the coordinate
	// size for ECDSA.
	SigLen int
}

var algorithms = []struct {
	// match are substrings that must all appear in the normalized reported
	// algorithm strings for this entry to apply.
	match []string
	alg   Algorithm
}{
	{[]string{"ECDSA", "P384", "SHA512"}, Algorithm{"ECDSA_P384_SHA512", crypto.SHA512, 96}},
	{[]string{"ECDSA", "P384", "SHA384"}, Algorithm{"ECDSA_P384_SHA384", crypto.SHA384, 96}},
	{[]string{"ECDSA", "P521"}, Algorithm{"ECDSA_P521_SHA512", crypto.SHA512, 132}},
	{[]string{"ECDSA", "P256"}, Algorithm{"ECDSA_P256_SHA256", crypto.SHA256, 64}},
}

// alternateDigests returns the other digests this build knows for the same
// signature width.
//
// SPDM negotiates MeasurementHashAlgo, which hashes measurement blocks, and
// BaseHashAlgo, which the signature is taken over. Redfish exposes one
// HashingAlgorithm field per action response, and vendors disagree on which of
// the two it names: the ConnectX IRoT targets report SHA-512 there while
// signing with SHA-384, so the declared value cannot be the last word. Trying
// the alternatives costs one hash each and either finds the digest the
// responder actually used or leaves the verdict exactly where it was.
func alternateDigests(alg Algorithm) []Algorithm {
	var out []Algorithm
	for _, candidate := range algorithms {
		if candidate.alg.SigLen == alg.SigLen && candidate.alg.Hash != alg.Hash {
			out = append(out, candidate.alg)
		}
	}
	return out
}

// ErrUnsupportedAlgorithm is a signing or hashing algorithm this build cannot
// verify. It is deliberately an error rather than a fallback: guessing the
// digest would produce a confident wrong answer.
type ErrUnsupportedAlgorithm struct {
	Signing string
	Hashing string
}

func (e *ErrUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("unsupported SPDM algorithms: signing %q, hashing %q", e.Signing, e.Hashing)
}

// normalize strips the punctuation and TPM_ALG_ prefixes that vendors vary on,
// so "TPM_ALG_ECDSA_ECC_NIST_P384" and "ECDSA-P384" compare equal.
func normalize(s string) string {
	s = strings.ToUpper(s)
	for _, cut := range []string{"_", "-", " ", "TPMALG", "ECCNIST"} {
		s = strings.ReplaceAll(s, cut, "")
	}
	return s
}

// ResolveAlgorithm picks the verification parameters for the algorithms a BMC
// reported. The hashing string is consulted first because the same signing curve
// is used with different digests.
func ResolveAlgorithm(signing, hashing string) (Algorithm, error) {
	hay := normalize(signing) + "|" + normalize(hashing)
	for _, candidate := range algorithms {
		all := true
		for _, needle := range candidate.match {
			if !strings.Contains(hay, needle) {
				all = false
				break
			}
		}
		if all {
			return candidate.alg, nil
		}
	}
	return Algorithm{}, &ErrUnsupportedAlgorithm{Signing: signing, Hashing: hashing}
}
