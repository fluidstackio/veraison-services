// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
// Package spdmtest builds synthetic SPDM responses for tests.
//
// It deliberately depends on nothing in internal/spdm and encodes the wire
// format from the specification independently. A shared encoder would hide an
// encoding bug from the parser that consumes it; two implementations that
// disagree fail a test instead.
package spdmtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	_ "crypto/sha256" // digest registration for crypto.Hash.New
	_ "crypto/sha512"
)

// DSP0274 wire constants.
const (
	codeMeasurements    = 0x60
	codeGetMeasurements = 0xE0
	nonceSize           = 32
	specDMTF            = 0x01
	attrSignature       = 0x01

	// OperationAllBlocks asks for every measurement block.
	OperationAllBlocks uint8 = 0xFF
)

// Responder is a synthetic SPDM responder with its own device identity.
type Responder struct {
	LeafKey *ecdsa.PrivateKey
	// Chain is DER, leaf first.
	Chain [][]byte
	// Roots anchors Chain.
	Roots *x509.CertPool
	// UnrelatedRoots anchors nothing in Chain, for negative tests.
	UnrelatedRoots *x509.CertPool
}

func selfSigned(t testing.TB, cn string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return key, cert, der
}

// NewResponder builds a responder with a two-certificate chain.
func NewResponder(t testing.TB) *Responder {
	t.Helper()

	rootKey, root, rootDER := selfSigned(t, "fsattest test device root")

	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "fsattest test responder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	_, other, _ := selfSigned(t, "unrelated root")
	unrelated := x509.NewCertPool()
	unrelated.AddCert(other)

	return &Responder{
		LeafKey:        leafKey,
		Chain:          [][]byte{leafDER, rootDER},
		Roots:          roots,
		UnrelatedRoots: unrelated,
	}
}

// Block is one measurement block to emit.
type Block struct {
	Index     uint8
	ValueType uint8
	Value     []byte
}

// DefaultBlocks is a representative record: two digests and one raw bit stream.
func DefaultBlocks() []Block {
	return []Block{
		{Index: 1, ValueType: 0x00, Value: make([]byte, 48)},
		{Index: 2, ValueType: 0x01, Value: make([]byte, 48)},
		{Index: 3, ValueType: 0x83, Value: []byte("raw-config-bits")},
	}
}

// Exchange is a prior request/response pair on the same SPDM context.
type Exchange struct {
	Request  []byte
	Response []byte
}

// Options controls one synthetic response.
type Options struct {
	// VersionByte is the packed SPDMVersion, 0x11 for 1.1.
	VersionByte byte
	Nonce       []byte
	SlotID      uint8
	Operation   uint8
	Blocks      []Block
	SigLen      int
	Hash        crypto.Hash
	Prior       []Exchange
	// WrongKey signs with a key the chain does not contain.
	WrongKey bool
	// CorruptRecord flips a measurement byte after signing.
	CorruptRecord bool
}

func (o *Options) withDefaults() {
	if o.VersionByte == 0 {
		o.VersionByte = 0x11
	}
	if o.Nonce == nil {
		o.Nonce = make([]byte, nonceSize)
	}
	if o.Operation == 0 {
		o.Operation = OperationAllBlocks
	}
	if o.Blocks == nil {
		o.Blocks = DefaultBlocks()
	}
	if o.SigLen == 0 {
		o.SigLen = 96
	}
	if o.Hash == 0 {
		o.Hash = crypto.SHA384
	}
}

// GetMeasurementsRequest encodes the request half of an exchange.
func GetMeasurementsRequest(version byte, operation, slotID uint8, nonce []byte) []byte {
	req := []byte{version, codeGetMeasurements, 0, operation}
	if len(nonce) > 0 {
		req[2] = attrSignature
		req = append(req, nonce...)
		req = append(req, slotID)
	}
	return req
}

func encodeRecord(blocks []Block) []byte {
	var record []byte
	for _, b := range blocks {
		body := []byte{b.ValueType}
		body = binary.LittleEndian.AppendUint16(body, uint16(len(b.Value))) //nolint:gosec // fixture sizes are small
		body = append(body, b.Value...)

		record = append(record, b.Index, specDMTF)
		record = binary.LittleEndian.AppendUint16(record, uint16(len(body))) //nolint:gosec // fixture sizes are small
		record = append(record, body...)
	}
	return record
}

// Build assembles a MEASUREMENTS response and signs it as the specification
// requires, so that a correct verifier accepts it.
func (r *Responder) Build(t testing.TB, o Options) []byte {
	t.Helper()
	o.withDefaults()

	record := encodeRecord(o.Blocks)

	prefix := []byte{o.VersionByte, codeMeasurements, byte(len(o.Blocks)), o.SlotID}
	prefix = append(prefix, byte(len(o.Blocks)))
	prefix = append(prefix, byte(len(record)), byte(len(record)>>8), byte(len(record)>>16))
	prefix = append(prefix, record...)
	prefix = append(prefix, o.Nonce...)
	prefix = binary.LittleEndian.AppendUint16(prefix, 0)

	transcript := make([]byte, 0, len(prefix)+64)
	for _, e := range o.Prior {
		transcript = append(transcript, e.Request...)
		transcript = append(transcript, e.Response...)
	}
	transcript = append(transcript, GetMeasurementsRequest(o.VersionByte, o.Operation, o.SlotID, o.Nonce)...)
	transcript = append(transcript, prefix...)

	key := r.LeafKey
	if o.WrongKey {
		other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generating wrong key: %v", err)
		}
		key = other
	}

	digester := o.Hash.New()
	digester.Write(transcript)
	sigR, sigS, err := ecdsa.Sign(rand.Reader, key, digester.Sum(nil))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	half := o.SigLen / 2
	sig := make([]byte, o.SigLen)
	sigR.FillBytes(sig[:half])
	sigS.FillBytes(sig[half:])

	out := append(prefix, sig...) //nolint:gocritic // a fresh buffer is intended
	if o.CorruptRecord {
		// Past the 4-byte header, NumberOfBlocks, the 3-byte record length, the
		// block header and the DMTF header: the first measurement value byte.
		out[4+1+3+4+3] ^= 0xFF
	}
	return out
}
