// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"
)

// Outcome is the three-state result of attempting offline verification.
//
// These are deliberately distinct values rather than a bool plus a reason. A
// signature that was never checked and a signature that checked out must not be
// representable by the same value, because an unverified signature reported as
// verified manufactures confidence that nothing downstream can recover from.
type Outcome string

const (
	// OutcomeVerified means the signature was checked and is good.
	OutcomeVerified Outcome = "verified"
	// OutcomeUnverifiableTranscript means the signature could not be checked
	// through this path, and nothing is claimed about its validity.
	OutcomeUnverifiableTranscript Outcome = "unverifiable_transcript"
	// OutcomeFailed means the signature was checked and is bad, or the response
	// could not be trusted for a structural reason.
	OutcomeFailed Outcome = "failed"
)

// NonceBinding records whether the verifier's nonce reached the signed
// transcript, which is what freshness rests on.
//
// It is a three-state value rather than a bool because the failure modes are not
// interchangeable: a responder that substitutes its own nonce cannot be
// distinguished, from the payload alone, from a stale payload answering an
// earlier request. Both mean freshness is unproven, and neither may be reported
// as bound.
type NonceBinding string

const (
	// NonceBindingVerifier means the nonce sent appears in the signed transcript.
	NonceBindingVerifier NonceBinding = "verifier_nonce_in_transcript"
	// NonceBindingSubstituted means the transcript carries a different requester
	// nonce. Observed on Dell iDRAC, which ignores the Redfish Nonce parameter
	// and generates its own for the SPDM exchange.
	NonceBindingSubstituted NonceBinding = "responder_substituted_nonce"
	// NonceBindingUnverifiable means the payload carried no request bytes, so
	// there is nowhere the caller's nonce could be checked. The MEASUREMENTS
	// response nonce is the responder's own and is not an echo.
	NonceBindingUnverifiable NonceBinding = "unverifiable_no_request_bytes"
)

// ErrNonceMismatch is retained for callers that treat a broken binding as fatal.
type ErrNonceMismatch struct {
	Expected []byte
	Got      []byte
}

func (e *ErrNonceMismatch) Error() string {
	return fmt.Sprintf("SPDM requester nonce mismatch: sent %x, transcript carries %x", e.Expected, e.Got)
}

// ErrNoCertChain is an empty or unparseable responder chain.
var ErrNoCertChain = errors.New("no usable responder certificate chain")

// Input is everything needed to appraise one measurement response offline.
type Input struct {
	// Response is the raw SignedMeasurements payload, byte for byte as received.
	Response []byte
	// CertChain is DER, leaf first.
	CertChain [][]byte
	// TrustAnchors verifies the chain. A nil pool skips chain verification and
	// caps the outcome, since an unanchored chain proves only self-consistency.
	TrustAnchors *x509.CertPool
	// Now overrides the clock for chain validity, for fixture stability.
	Now time.Time

	SigningAlgorithm string
	HashingAlgorithm string

	// Nonce is the verifier-issued nonce that was sent.
	Nonce []byte
	// SlotID and Operation are the request parameters, needed to rebuild the
	// request half of the transcript.
	SlotID    uint8
	Operation uint8
	// Prior carries exchanges the responder made on the same SPDM context before
	// this one. See BuildTranscript.
	Prior []Exchange

	// PrimingPayload is the payload a vendor's priming post returned, already a
	// complete request/response pair. On a responder that keeps one SPDM context
	// across both posts it is the prior half of L1/L2, so it is tried as a prefix
	// when the signature does not verify over our exchange alone.
	PrimingPayload []byte
}

// Result reports what verification established.
type Result struct {
	Outcome   Outcome
	Version   Version
	Algorithm string
	// Reason explains any outcome other than verified.
	Reason string
	// ChainVerified is whether the responder chain built a path to a trust
	// anchor. False when no anchors were supplied.
	ChainVerified bool
	// RequestPrepended is whether the responder supplied the request bytes. When
	// true the transcript was read rather than reconstructed, which removes the
	// largest assumption in an offline verification.
	RequestPrepended bool
	// PriorExchanges counts complete exchanges the payload carried before the
	// signed one, which is what answers whether the responder reuses a context.
	PriorExchanges int
	// DigestCorrected is true when the signature verified under a digest other
	// than the one the BMC reported. The measurements are sound, but the
	// responder's advertised algorithms cannot be taken at face value, which is
	// worth surfacing rather than silently absorbing.
	DigestCorrected bool
	// SignatureLittleEndian is true when r and s verified only as little-endian
	// integers. Accepted for SPDM 1.0 responders alone; see signatureEncodings.
	SignatureLittleEndian bool
	// NonceBinding says whether the verifier's nonce reached the transcript.
	NonceBinding NonceBinding
	// NonceMatched is true only for NonceBindingVerifier.
	NonceMatched bool
	Blocks       int
	// Measurements is the parsed response, for callers that appraise blocks.
	Measurements *Measurements
}

// ClassifyNonce decides the binding without failing the appraisal. A responder
// that ignores the supplied nonce still returns genuine measurements over a
// valid signature; what it does not provide is verifier-controlled freshness,
// and that is recorded rather than treated as a bad device.
func ClassifyNonce(sent, inTranscript []byte) NonceBinding {
	if len(inTranscript) == 0 {
		return NonceBindingUnverifiable
	}
	if len(sent) > 0 && subtle.ConstantTimeCompare(sent, inTranscript) == 1 {
		return NonceBindingVerifier
	}
	return NonceBindingSubstituted
}

func failed(reason string, args ...any) (Result, error) {
	return Result{Outcome: OutcomeFailed, Reason: fmt.Sprintf(reason, args...)}, nil
}

// Verify parses a MEASUREMENTS response and attempts offline signature
// verification.
//
// A returned error is a problem with the inputs, such as an algorithm this build
// cannot handle. A verification that ran and did not succeed is a Result with a
// non-verified Outcome and no error, because "this device failed appraisal" is
// an answer rather than a malfunction. The one exception is a nonce mismatch,
// which is returned as an error so that no caller can treat it as a soft result.
func Verify(in Input) (Result, error) {
	alg, err := ResolveAlgorithm(in.SigningAlgorithm, in.HashingAlgorithm)
	if err != nil {
		return Result{}, err
	}

	payload, err := ParsePayload(in.Response, alg.SigLen)
	if err != nil {
		return Result{Outcome: OutcomeFailed, Algorithm: alg.Name, Reason: err.Error()}, nil
	}
	m := payload.Final

	res := Result{
		Version:          m.Version,
		Algorithm:        alg.Name,
		Blocks:           len(m.Blocks),
		Measurements:     m,
		RequestPrepended: payload.RequestPrepended,
	}

	// Freshness is decided by the requester nonce inside the transcript. The
	// response nonce is the responder's own and would never match, so checking
	// against it would fail on healthy hardware.
	res.NonceBinding = ClassifyNonce(in.Nonce, payload.RequestNonce)
	res.NonceMatched = res.NonceBinding == NonceBindingVerifier

	leaf, chainErr := verifyChain(in.CertChain, in.TrustAnchors, in.Now)
	if leaf == nil {
		res.Outcome = OutcomeFailed
		res.Reason = fmt.Sprintf("responder certificate chain unusable: %v", chainErr)
		return res, nil
	}
	if in.TrustAnchors != nil {
		if chainErr != nil {
			res.Outcome = OutcomeFailed
			res.Reason = fmt.Sprintf("responder chain does not reach a trust anchor: %v", chainErr)
			return res, nil
		}
		res.ChainVerified = true
	}

	// The version gate. A 1.2+ responder reached over Redfish cannot have its
	// transcript rebuilt, so no signature claim is made at all — not even a
	// failed one, which would imply the check was meaningful.
	if !m.Version.TranscriptReconstructible() {
		res.Outcome = OutcomeUnverifiableTranscript
		res.Reason = fmt.Sprintf(
			"SPDM %s covers the VCA exchange in L1/L2, which Redfish does not expose; the signature cannot be checked through this path",
			m.Version)
		return res, nil
	}

	// When the responder returned the request bytes, the transcript is given
	// rather than inferred: no assumption about the request encoding, and no
	// assumption that the responder used a fresh SPDM context. Only fall back to
	// reconstruction when the payload carried the response alone.
	transcript := payload.Transcript()
	if !payload.RequestPrepended {
		request := BuildGetMeasurements(m.Version, in.Operation, in.SlotID, in.Nonce)
		transcript = BuildTranscript(in.Prior, request, m)
	}

	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return failed("responder leaf key is %T, not ECDSA", leaf.PublicKey)
	}
	res.PriorExchanges = len(payload.Prior)

	// Two things the responder does not reliably tell us are tried here rather
	// than assumed: whether it signed over a context that began before our
	// exchange, and which digest it actually used. A vendor needing two posts
	// hands back the preceding exchange in the priming payload, itself a
	// request/response pair, so it prefixes L1/L2 verbatim. See alternateDigests
	// for why the reported hash is not decisive.
	transcripts := [][]byte{transcript}
	if len(in.PrimingPayload) > 0 {
		spanning := make([]byte, 0, len(in.PrimingPayload)+len(transcript))
		spanning = append(spanning, in.PrimingPayload...)
		spanning = append(spanning, transcript...)
		transcripts = append(transcripts, spanning)
	}

	for _, enc := range signatureEncodings(m.Version) {
		sig := enc.decode(m.Signature)
		for _, cand := range append([]Algorithm{alg}, alternateDigests(alg)...) {
			for i, candidate := range transcripts {
				if !verifyECDSA(pub, cand, candidate, sig) {
					continue
				}
				res.Algorithm = cand.Name
				res.DigestCorrected = cand.Hash != alg.Hash
				res.SignatureLittleEndian = enc.littleEndian
				if i > 0 {
					res.PriorExchanges++
				}
				res.Outcome = OutcomeVerified
				return res, nil
			}
		}
	}

	res.Outcome = OutcomeFailed
	res.Reason = "signature does not verify over the reconstructed L1/L2 transcript"
	return res, nil
}

// verifyChain parses the DER chain and, when anchors are supplied, builds a path
// to one. The leaf is returned even when the path fails so the caller can report
// which certificate was rejected.
func verifyChain(chain [][]byte, anchors *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, ErrNoCertChain
	}
	certs := make([]*x509.Certificate, 0, len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		acceptDICEExtensions(cert)
		certs = append(certs, cert)
	}
	leaf := selectLeaf(certs)

	if anchors == nil {
		return leaf, nil
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		if cert != leaf {
			intermediates.AddCert(cert)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         anchors,
		Intermediates: intermediates,
		CurrentTime:   now,
		// SPDM responder certificates are device identity, not TLS server
		// identity, and carry no usable EKU.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return leaf, err
}

type signatureEncoding struct {
	littleEndian bool
	decode       func([]byte) []byte
}

// signatureEncodings lists the byte orders an ECDSA r||s signature is tried in.
//
// DSP0274 1.0 defines the ECDSA signature as r followed by s without fixing
// their byte order; 1.2 settled on big-endian, which is what 1.1 and later
// responders use. The Intel Xeon GNR S3M answers at 1.0 with each half
// little-endian: its signature verifies over exactly the transcript it
// returns, under its own leaf key and hash, only in that order (every other
// key, transcript, digest and order was tried; established 2026-09-23 on
// wdl101-b300-mach1 CPU.Socket.0).
//
// The fallback is confined to 1.0, where the order was genuinely ambiguous. It
// does not weaken anything: either order still needs a signature the device's
// key produced over our transcript. A later responder signing little-endian is
// non-conformant and fails, rather than being absorbed here.
func signatureEncodings(v Version) []signatureEncoding {
	encs := []signatureEncoding{{decode: func(sig []byte) []byte { return sig }}}
	if v == V10 {
		encs = append(encs, signatureEncoding{littleEndian: true, decode: reverseHalves})
	}
	return encs
}

// reverseHalves turns little-endian r||s into big-endian r||s.
func reverseHalves(sig []byte) []byte {
	out := make([]byte, len(sig))
	half := len(sig) / 2
	for i := 0; i < half; i++ {
		out[half-1-i] = sig[i]
		out[len(sig)-1-i] = sig[half+i]
	}
	return out
}

// diceExtensions are the TCG DICE certificate extensions this verifier accounts
// for (TCG DICE Attestation Architecture, tcg-dice arc 2.23.133.5.4). The spec
// marks TcbInfo critical so that a verifier which does not understand DICE
// refuses the chain rather than ignoring what it records; Go's x509 does
// exactly that, which is how the Intel CPU responders failed with "unhandled
// critical extension".
//
// Accepting them is a claim about this code, so it is deliberately narrow:
// what they record is layered firmware identity, the same kind of fact as the
// SPDM measurement blocks, and like those it is surfaced but not yet compared
// against reference values. Any other unknown critical extension still fails.
var diceExtensions = []asn1.ObjectIdentifier{
	{2, 23, 133, 5, 4, 1}, // tcg-dice-TcbInfo
	{2, 23, 133, 5, 4, 4}, // tcg-dice-Ueid
	{2, 23, 133, 5, 4, 5}, // tcg-dice-MultiTcbInfo
}

func acceptDICEExtensions(cert *x509.Certificate) {
	kept := cert.UnhandledCriticalExtensions[:0]
	for _, oid := range cert.UnhandledCriticalExtensions {
		if !slices.ContainsFunc(diceExtensions, oid.Equal) {
			kept = append(kept, oid)
		}
	}
	cert.UnhandledCriticalExtensions = kept
}

// selectLeaf picks the end-entity certificate out of a responder chain without
// relying on its order.
//
// SPDM defines the chain root-first, and the ConnectX NICs present it that way,
// but the NVIDIA GPU and ERoT targets on the same machine hand back the exact
// reverse. Taking certs[0] therefore verified NIC measurements against the
// root CA's key and reported a signature failure that was really a chain-order
// assumption.
//
// The leaf is the certificate that issued nothing else in the chain. A
// self-signed root names itself as issuer, so it is never mistaken for one.
// A chain that is entirely self-referential falls back to the first entry,
// which keeps the single-certificate case working.
func selectLeaf(certs []*x509.Certificate) *x509.Certificate {
	issuers := make(map[string]struct{}, len(certs))
	for _, cert := range certs {
		issuers[string(cert.RawIssuer)] = struct{}{}
	}
	for _, cert := range certs {
		if _, isIssuer := issuers[string(cert.RawSubject)]; !isIssuer {
			return cert
		}
	}
	return certs[0]
}

// verifyECDSA checks a raw r||s signature, the encoding SPDM uses. Go's ecdsa
// package expects the components, not the ASN.1 wrapper, so the halves are split
// at the algorithm's fixed width rather than parsed.
func verifyECDSA(pub *ecdsa.PublicKey, alg Algorithm, message, sig []byte) bool {
	if len(sig) != alg.SigLen {
		return false
	}
	half := alg.SigLen / 2

	digester := alg.Hash.New()
	digester.Write(message)
	digest := digester.Sum(nil)

	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return ecdsa.Verify(pub, digest, r, s)
}
