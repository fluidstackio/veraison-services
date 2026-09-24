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

// Reference values are keyed by chip and component class (see refvals.go):
// class vendor is the CN issuing the responder's leaf, class model the class.
func validateReferenceValueEnvironment(env *comid.Environment) error {
	if env.Class == nil || env.Class.Vendor == nil || env.Class.Model == nil {
		return errors.New("class needs vendor (the chip) and model (the component class)")
	}
	if env.Class.ClassID != nil || env.Instance != nil || env.Group != nil {
		return errors.New("only class vendor and model are used; class ID, instance and group must not be set")
	}
	return nil
}

// Each reference value is one SPDM measurement block: keyed by its index,
// carrying either the digests it may equal or the raw bitstream it must equal.
func validateMeasurements(measurements []comid.Measurement) error {
	for i, m := range measurements {
		if m.Key == nil || m.Key.Type() != comid.UintType {
			return fmt.Errorf("measurement %d: key must be the SPDM measurement index, as uint", i)
		}
		idx, err := m.Key.GetKeyUint()
		if err != nil {
			return fmt.Errorf("measurement %d: %w", i, err)
		}
		if idx < 1 || idx > 0xFE {
			return fmt.Errorf("measurement %d: SPDM index %d out of range 1..254", i, idx)
		}
		hasDigests := m.Val.Digests != nil && len(*m.Val.Digests) > 0
		hasRaw := m.Val.RawValue != nil
		if hasDigests == hasRaw {
			return fmt.Errorf("measurement %d (index %d): needs exactly one of digests or raw-value", i, idx)
		}
	}
	return nil
}

func init() {
	profileID, err := corim.NewProfileFromString(ProfileString)
	if err != nil {
		panic(err)
	}

	validator := &common.TriplesValidator{
		TAEnviromentValidator:     validateTrustAnchorEnvironment,
		RefValEnviromentValidator: validateReferenceValueEnvironment,
		CryptoKeysValidator:       validateCryptoKeys,
		MeasurementsValidator:     validateMeasurements,
	}
	extMap := extensions.NewMap().Add(comid.ExtTriples, validator)

	if err := corim.RegisterProfile(profileID, extMap); err != nil {
		panic(err)
	}
}
