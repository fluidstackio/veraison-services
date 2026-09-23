// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"errors"
	"fmt"

	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/corim/extensions"
	"github.com/veraison/services/scheme/common"
)

// ProfileString identifies CoRIMs for this scheme. Namespaced for the same
// reason as the evidence media type: Veraison refuses two plugins claiming one
// profile, and an upstream SPDM scheme may land later.
const ProfileString = "tag:fluidstack.io,2026:spdm-redfish"

// A trust anchor is the vendor root an SPDM responder's certificate chain ends
// at, keyed by that root's subject: class model is its CN, class vendor its O
// when it has one. GetTrustAnchorIDs derives the same key from the evidence
// (rootClass), so the two must agree on when vendor is present.
func validateTrustAnchorEnvironment(env *comid.Environment) error {
	if env.Class == nil {
		return errors.New("missing class")
	}
	if env.Class.Model == nil {
		return errors.New("missing model (the root certificate's CN)")
	}
	if env.Class.ClassID != nil {
		return errors.New("class ID must not be set: trust anchors are keyed by the root's subject")
	}
	if env.Instance != nil {
		return errors.New("instance must not be set: a trust anchor here is a vendor root, not a device")
	}
	return nil
}

func validateCryptoKeys(keys []*comid.CryptoKey) error {
	if len(keys) != 1 {
		return fmt.Errorf("expected exactly one key, found %d", len(keys))
	}
	if keys[0].Type() != comid.PKIXBase64CertType {
		return fmt.Errorf("key must be a PKIX certificate, found: %s", keys[0].Type())
	}
	return nil
}

func init() {
	profileID, err := corim.NewProfileFromString(ProfileString)
	if err != nil {
		panic(err)
	}

	validator := &common.TriplesValidator{
		TAEnviromentValidator: validateTrustAnchorEnvironment,
		CryptoKeysValidator:   validateCryptoKeys,
		// Reference values are not appraised yet; see AppraiseClaims. Refusing
		// them keeps a provisioned CoRIM from implying a comparison that does
		// not happen.
		DisallowRefVals: true,
	}
	extMap := extensions.NewMap().Add(comid.ExtTriples, validator)

	if err := corim.RegisterProfile(profileID, extMap); err != nil {
		panic(err)
	}
}
