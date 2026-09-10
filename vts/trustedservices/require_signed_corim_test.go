package trustedservices

import (
	"testing"

	"github.com/veraison/services/log"
)

// The advertisement must match what SubmitEndorsements will actually accept:
// listing application/rim+cbor and then refusing it makes a client discover the
// policy from a failed submission rather than from media-type negotiation.
func TestRequireSignedCorimFiltersAdvertisedMediaTypes(t *testing.T) {
	in := []string{
		`application/rim+cbor; profile="tag:example.com,2025:p"`,
		`application/rim+cose; profile="tag:example.com,2025:p"`,
		`application/rim+cbor; profile="tag:other.com,2025:q"`,
		`application/rim+cose; profile="tag:other.com,2025:q"`,
	}

	for _, tc := range []struct {
		name       string
		require    bool
		wantLen    int
		wantNoCbor bool
	}{
		{"off keeps both forms", false, 4, false},
		{"on drops the unsigned form", true, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &GRPC{requireSignedCorim: tc.require, logger: log.Named("test")}
			got := g.filterProvisioningMediaTypes(in)
			if len(got) != tc.wantLen {
				t.Fatalf("got %d media types, want %d: %v", len(got), tc.wantLen, got)
			}
			if tc.wantNoCbor {
				for _, mt := range got {
					if mt[:len("application/rim+cbor")] == "application/rim+cbor" {
						t.Errorf("unsigned form still advertised: %s", mt)
					}
				}
			}
		})
	}
}
