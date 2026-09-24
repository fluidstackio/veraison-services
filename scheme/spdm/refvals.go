// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/veraison/corim/comid"
	"github.com/veraison/ear"
)

// Reference values are keyed by what the device is, in two parts:
//
//   - vendor: the CN of the certificate that issued the responder's leaf -- the
//     chip, from the signed chain ("GB110 A01 FSP BROM", "CEC173x-S2 BROM CA");
//   - model: the Redfish component class ("HGX_IRoT_GPU" from HGX_IRoT_GPU_3).
//
// The class alone is BMC-supplied and unsigned; the chain alone cannot tell
// siblings apart (every HGX ERoT is the same CEC173x). Together, a lying BMC
// can at most have one ERoT compared against another ERoT's values, and it
// would still need that device to sign exactly those measurements.

var instanceSuffix = regexp.MustCompile(`(_\d+|\.\d+)$`)

// componentClass drops the instance number: HGX_IRoT_GPU_3 -> HGX_IRoT_GPU,
// CPU.Socket.1 -> CPU.Socket.
func componentClass(targetID string) string {
	return instanceSuffix.ReplaceAllString(targetID, "")
}

// chipIdentity is the CN of the leaf's issuer, found by issuance rather than
// position (responders disagree on chain order).
func chipIdentity(chain [][]byte) (string, error) {
	certs := make([]*x509.Certificate, 0, len(chain))
	issuers := map[string]bool{}
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", fmt.Errorf("parsing certificate %d: %w", i, err)
		}
		certs = append(certs, c)
		issuers[string(c.RawIssuer)] = true
	}
	for _, c := range certs {
		if !issuers[string(c.RawSubject)] {
			if c.Issuer.CommonName == "" {
				return "", errors.New("responder leaf's issuer has no CN")
			}
			return c.Issuer.CommonName, nil
		}
	}
	return "", errors.New("no leaf in chain")
}

// scoredClaim is which trust claim a measurement block speaks to, from its
// DMTF value type (DSP0274 Table "DMTF measurement specification format").
type scoredClaim int

const (
	claimExecutables scoredClaim = iota
	claimConfiguration
)

func claimFor(dmtfType int) scoredClaim {
	switch dmtfType & 0x7F {
	case 0x00, 0x01, 0x06, 0x07: // immutable ROM, mutable firmware, version, SVN
		return claimExecutables
	default: // hardware and firmware configuration, manifest, device mode
		return claimConfiguration
	}
}

func (c scoredClaim) String() string {
	if c == claimExecutables {
		return "executables"
	}
	return "configuration"
}

type refValue struct {
	digests [][]byte // any one may match
	raw     []byte
	mask    []byte
	// vendor names who authorized the value: the CN of the measurement's
	// authorized-by certificate. Empty means our own baseline -- a value
	// captured from the fleet, which catches change but vouches for nothing.
	vendor string
}

func (r refValue) matches(observed []byte) bool {
	if r.raw != nil {
		if r.mask == nil {
			return bytes.Equal(r.raw, observed)
		}
		if len(observed) != len(r.raw) || len(r.mask) != len(r.raw) {
			return false
		}
		for i := range r.raw {
			if observed[i]&r.mask[i] != r.raw[i]&r.mask[i] {
				return false
			}
		}
		return true
	}
	for _, d := range r.digests {
		if bytes.Equal(d, observed) {
			return true
		}
	}
	return false
}

func (r refValue) String() string {
	if r.raw != nil {
		return hex.EncodeToString(r.raw)
	}
	if len(r.digests) == 1 {
		return hex.EncodeToString(r.digests[0])
	}
	return fmt.Sprintf("one of %d digests", len(r.digests))
}

// referenceValues flattens the endorsements into index -> expected value. Two
// endorsements naming the same index must agree; otherwise which one applies
// would depend on store order.
func referenceValues(endorsements []*comid.ValueTriple) (map[uint64]refValue, error) {
	refs := map[uint64]refValue{}
	for _, vt := range endorsements {
		for _, m := range vt.Measurements.Values {
			if m.Key == nil {
				return nil, errors.New("reference value without a measurement index")
			}
			idx, err := m.Key.GetKeyUint()
			if err != nil {
				return nil, fmt.Errorf("measurement key: %w", err)
			}
			var rv refValue
			switch {
			case m.Val.RawValue != nil:
				rv.raw = m.Val.RawValue.Bytes()
				rv.mask = m.Val.RawValue.Mask()
			case m.Val.Digests != nil:
				for _, d := range *m.Val.Digests {
					rv.digests = append(rv.digests, d.Value)
				}
			default:
				return nil, fmt.Errorf("reference value for index %d has neither digests nor a raw value", idx)
			}
			rv.vendor = authorizer(m.AuthorizedBy)
			if prev, ok := refs[idx]; ok && prev.String() != rv.String() {
				return nil, fmt.Errorf("conflicting reference values for index %d", idx)
			}
			refs[idx] = rv
		}
	}
	return refs, nil
}

// authorizer is the CN of the first certificate in a measurement's
// authorized-by, or "" when there is none. A key that is not a certificate still
// counts as authorized, under a placeholder, rather than silently as baseline.
func authorizer(keys *comid.CryptoKeys) string {
	if keys == nil || len(*keys) == 0 {
		return ""
	}
	k := (*keys)[0]
	if k.Type() == comid.PKIXBase64CertType {
		der := []byte(k.String())
		if blk, _ := pem.Decode(der); blk != nil {
			der = blk.Bytes
		}
		if c, err := x509.ParseCertificate(der); err == nil && c.Subject.CommonName != "" {
			return c.Subject.CommonName
		}
	}
	if k.Type() == comid.PKIXBase64KeyType {
		der := []byte(k.String())
		if blk, _ := pem.Decode(der); blk != nil {
			der = blk.Bytes
		}
		if _, err := x509.ParsePKIXPublicKey(der); err == nil {
			// A key has no name; its SPKI thumbprint identifies it. Tooling
			// that knows the vendor (Dell's PGP release key, say) can map it.
			sum := sha256.Sum256(der)
			return "key sha256:" + hex.EncodeToString(sum[:8])
		}
	}
	return "authorized key (" + k.Type() + ")"
}

type observedBlock struct {
	dmtfType int
	value    []byte
}

// observedBlocks reads the measurement claims ExtractClaims produced. Claims
// cross the plugin RPC boundary as JSON, so numbers arrive as float64.
func observedBlocks(claims map[string]any) (map[uint64]observedBlock, error) {
	raw, ok := claims["measurements"].([]any)
	if !ok {
		return nil, errors.New("claims carry no measurements")
	}
	out := make(map[uint64]observedBlock, len(raw))
	for _, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("measurement claim is %T", e)
		}
		idx, ok1 := asUint(m["index"])
		typ, ok2 := asUint(m["dmtf-value-type"])
		hexv, ok3 := m["value"].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("malformed measurement claim %v", m)
		}
		v, err := hex.DecodeString(hexv)
		if err != nil {
			return nil, fmt.Errorf("measurement %d value: %w", idx, err)
		}
		out[idx] = observedBlock{dmtfType: int(typ), value: v}
	}
	return out, nil
}

func asUint(v any) (uint64, bool) {
	switch n := v.(type) {
	case int:
		return uint64(n), n >= 0 //nolint:gosec // sign checked
	case int64:
		return uint64(n), n >= 0 //nolint:gosec // sign checked
	case uint64:
		return n, true
	case float64:
		return uint64(n), n >= 0 && n == float64(uint64(n))
	}
	return 0, false
}

type mismatch struct {
	Index    uint64 `json:"index"`
	Claim    string `json:"claim"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}

type comparison struct {
	scored     map[scoredClaim]bool // claim -> had at least one reference value
	failed     map[scoredClaim]bool
	matched    int
	mismatches []mismatch
	unscored   int
	// matches by provenance, per claim: vendor-authorized or our baseline
	vendorBacked map[scoredClaim]int
	baseline     map[scoredClaim]int
	vendors      map[string]bool
}

func compare(refs map[uint64]refValue, observed map[uint64]observedBlock) comparison {
	c := comparison{
		scored: map[scoredClaim]bool{}, failed: map[scoredClaim]bool{},
		vendorBacked: map[scoredClaim]int{}, baseline: map[scoredClaim]int{}, vendors: map[string]bool{},
	}
	indices := make([]uint64, 0, len(refs))
	for i := range refs {
		indices = append(indices, i)
	}
	sort.Slice(indices, func(a, b int) bool { return indices[a] < indices[b] })

	for _, idx := range indices {
		ref := refs[idx]
		blk, present := observed[idx]
		// An absent block has no DMTF type to classify it by, so it is scored
		// against configuration. Either way it is a mismatch.
		claim := claimConfiguration
		if present {
			claim = claimFor(blk.dmtfType)
		}
		c.scored[claim] = true
		switch {
		case !present:
			c.failed[claim] = true
			c.mismatches = append(c.mismatches, mismatch{idx, claim.String(), ref.String(), "absent"})
		case ref.matches(blk.value):
			c.matched++
			if ref.vendor != "" {
				c.vendorBacked[claim]++
				c.vendors[ref.vendor] = true
			} else {
				c.baseline[claim]++
			}
		default:
			c.failed[claim] = true
			c.mismatches = append(c.mismatches, mismatch{idx, claim.String(), ref.String(), hex.EncodeToString(blk.value)})
		}
	}
	for idx := range observed {
		if _, ok := refs[idx]; !ok {
			c.unscored++
		}
	}
	return c
}

// apply sets the executables and configuration claims from a comparison. A
// claim with no reference values is left unset rather than approved.
//
// A mismatch is "unrecognized", not "contraindicated": the firmware is not the
// known-good build, which is not the same as known to be bad.
func (c comparison) apply(tv *ear.TrustVector) {
	if c.scored[claimExecutables] {
		tv.Executables = ear.ApprovedRuntimeClaim
		if c.failed[claimExecutables] {
			tv.Executables = ear.UnrecognizedRuntimeClaim
		}
	}
	if c.scored[claimConfiguration] {
		tv.Configuration = ear.ApprovedConfigClaim
		if c.failed[claimConfiguration] {
			tv.Configuration = ear.UnsafeConfigClaim
		}
	}
}

func (c comparison) policyClaims() map[string]any {
	mm := make([]any, 0, len(c.mismatches))
	for _, m := range c.mismatches {
		mm = append(mm, map[string]any{
			"index": m.Index, "claim": m.Claim, "expected": m.Expected, "observed": m.Observed,
		})
	}
	vendors := make([]string, 0, len(c.vendors))
	for v := range c.vendors {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)
	prov := func(cl scoredClaim) map[string]any {
		return map[string]any{"vendor-backed": c.vendorBacked[cl], "baseline": c.baseline[cl]}
	}
	return map[string]any{
		"reference-values": map[string]any{
			"matched":    c.matched,
			"mismatched": mm,
			"unscored":   c.unscored,
			// Where each match's expected value came from. Baseline matches
			// are scored as known good by policy, but they only prove nothing
			// changed; vendor-backed ones prove the vendor published the value.
			"provenance": map[string]any{
				"executables":   prov(claimExecutables),
				"configuration": prov(claimConfiguration),
				"vendors":       vendors,
			},
		},
	}
}
