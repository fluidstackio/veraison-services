// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import "fmt"

// Version is the SPDMVersion byte: high nibble major, low nibble minor.
type Version uint8

const (
	V10 Version = 0x10
	V11 Version = 0x11
	V12 Version = 0x12
	V13 Version = 0x13
)

func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v>>4, v&0x0f)
}

// TranscriptReconstructible reports whether L1/L2 can be rebuilt from what
// Redfish exposes.
//
// For 1.0 and 1.1 the transcript is the GET_MEASUREMENTS requests and
// MEASUREMENTS responses, and the collector authored the request parameters, so
// it can rebuild the request bytes. From 1.2 the transcript additionally covers
// the VCA exchange — GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS and
// their responses — which the BMC performs as requester and Redfish does not
// surface. On those responders the signature cannot be verified through this
// path at all, and nothing in the response says so: it presents as an inability
// to reproduce the digest.
func (v Version) TranscriptReconstructible() bool {
	return v == V10 || v == V11
}

// ParseVersion converts a reported version string such as "1.1.0" to a Version.
// The Redfish Version field is decimal-dotted while the wire byte is packed
// nibbles, so the two representations have to be reconciled somewhere.
func ParseVersion(s string) (Version, error) {
	var major, minor int
	if _, err := fmt.Sscanf(s, "%d.%d", &major, &minor); err != nil {
		return 0, fmt.Errorf("parsing SPDM version %q: %w", s, err)
	}
	if major < 0 || major > 0x0f || minor < 0 || minor > 0x0f {
		return 0, fmt.Errorf("SPDM version %q out of range", s)
	}
	return Version(major<<4 | minor), nil //nolint:gosec // bounds checked above
}
