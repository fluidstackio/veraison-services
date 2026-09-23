// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package spdm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire constants from DSP0274.
const (
	// codeMeasurements is the RequestResponseCode of a MEASUREMENTS response.
	codeMeasurements = 0x60
	// codeGetMeasurements is the RequestResponseCode of a GET_MEASUREMENTS request.
	codeGetMeasurements = 0xE0

	// NonceSize is fixed by the specification, and matches the 32 bytes the
	// Veraison session issues.
	NonceSize = 32

	// measurementSpecDMTF is bit 0 of MeasurementSpecification.
	measurementSpecDMTF = 0x01

	// headerSize covers SPDMVersion, RequestResponseCode, Param1 and Param2.
	headerSize = 4
	// recordLengthSize is the width of MeasurementRecordLength, a 24-bit
	// little-endian field.
	recordLengthSize = 3
	// opaqueLengthSize is the width of OpaqueDataLength.
	opaqueLengthSize = 2
	// blockHeaderSize covers Index, MeasurementSpecification and MeasurementSize.
	blockHeaderSize = 4
	// dmtfHeaderSize covers DMTFSpecMeasurementValueType and ...ValueSize.
	dmtfHeaderSize = 3
)

// ErrMalformed is any structural failure to parse a response. It is distinct
// from a verification failure: the caller treats "this is not a MEASUREMENTS
// response" differently from "this signature does not check out".
var ErrMalformed = errors.New("malformed SPDM MEASUREMENTS response")

// Block is one measurement block.
type Block struct {
	Index                int
	Specification        uint8
	DMTFValueType        uint8
	DMTFValueRepresented bool
	// Value is the measurement itself, aliasing the response buffer. It is never
	// modified.
	Value []byte
	// Raw is the whole block including its header, needed to reproduce the
	// record byte for byte.
	Raw []byte
}

// IsDigest reports whether the DMTF value type marks this block as a digest
// rather than a raw bit stream. Bit 7 set means raw.
func (b Block) IsDigest() bool {
	return b.DMTFValueRepresented && b.DMTFValueType&0x80 == 0
}

// Measurements is a parsed MEASUREMENTS response. Every []byte field aliases the
// original response buffer rather than copying, so nothing covered by the
// signature is ever re-serialized.
type Measurements struct {
	Version    Version
	Param1     uint8
	Param2     uint8
	SlotID     uint8
	NumBlocks  uint8
	Record     []byte
	Blocks     []Block
	Nonce      []byte
	OpaqueData []byte
	Signature  []byte

	// SignedPrefix is everything the signature covers within this response: the
	// full message with the signature removed. The transcript is built from
	// this, so it is retained rather than recomputed.
	SignedPrefix []byte
	// Raw is the complete response as received.
	Raw []byte
}

// ParseMeasurements decodes a MEASUREMENTS response.
//
// The signature length is not carried on the wire; it is implied by the
// negotiated algorithm, which Redfish reports out of band. sigLen must therefore
// be supplied by the caller, and a wrong value shows up here as a length
// inconsistency rather than as a silent misparse.
func ParseMeasurements(buf []byte, sigLen int) (*Measurements, error) {
	if sigLen <= 0 {
		return nil, fmt.Errorf("%w: signature length %d is not usable", ErrMalformed, sigLen)
	}
	if len(buf) < headerSize {
		return nil, fmt.Errorf("%w: %d bytes is shorter than the header", ErrMalformed, len(buf))
	}

	m := &Measurements{
		Version: Version(buf[0]),
		Param1:  buf[2],
		Param2:  buf[3],
		Raw:     buf,
	}
	if code := buf[1]; code != codeMeasurements {
		return nil, fmt.Errorf("%w: RequestResponseCode 0x%02X is not MEASUREMENTS", ErrMalformed, code)
	}
	// Param2 carries the slot id in its low nibble.
	m.SlotID = m.Param2 & 0x0f

	off := headerSize
	if len(buf) < off+1+recordLengthSize {
		return nil, fmt.Errorf("%w: truncated before MeasurementRecordLength", ErrMalformed)
	}
	m.NumBlocks = buf[off]
	off++

	recordLen := int(buf[off]) | int(buf[off+1])<<8 | int(buf[off+2])<<16
	off += recordLengthSize

	if err := needs(buf, off, recordLen, "MeasurementRecord"); err != nil {
		return nil, err
	}
	m.Record = buf[off : off+recordLen]
	off += recordLen

	if err := needs(buf, off, NonceSize, "Nonce"); err != nil {
		return nil, err
	}
	m.Nonce = buf[off : off+NonceSize]
	off += NonceSize

	if err := needs(buf, off, opaqueLengthSize, "OpaqueDataLength"); err != nil {
		return nil, err
	}
	opaqueLen := int(binary.LittleEndian.Uint16(buf[off : off+opaqueLengthSize]))
	off += opaqueLengthSize

	if err := needs(buf, off, opaqueLen, "OpaqueData"); err != nil {
		return nil, err
	}
	m.OpaqueData = buf[off : off+opaqueLen]
	off += opaqueLen

	if err := needs(buf, off, sigLen, "Signature"); err != nil {
		return nil, err
	}
	m.SignedPrefix = buf[:off]
	m.Signature = buf[off : off+sigLen]
	off += sigLen

	if off != len(buf) {
		return nil, fmt.Errorf("%w: %d trailing bytes after the signature", ErrMalformed, len(buf)-off)
	}

	blocks, err := parseRecord(m.Record)
	if err != nil {
		return nil, err
	}
	if int(m.NumBlocks) != len(blocks) {
		return nil, fmt.Errorf("%w: NumberOfBlocks is %d but the record holds %d",
			ErrMalformed, m.NumBlocks, len(blocks))
	}
	m.Blocks = blocks
	return m, nil
}

// HasPrependedRequest reports whether a payload begins with a GET_MEASUREMENTS
// request rather than the MEASUREMENTS response.
//
// This answers one of the validation gate questions directly: if a BMC returns
// the request bytes alongside the response, the transcript does not have to be
// reconstructed from stored parameters at all, and a whole class of doubt about
// whether we rebuilt it correctly disappears.
func HasPrependedRequest(buf []byte) bool {
	return len(buf) >= headerSize && buf[1] == codeGetMeasurements
}

func needs(buf []byte, off, n int, field string) error {
	if n < 0 {
		return fmt.Errorf("%w: negative length for %s", ErrMalformed, field)
	}
	if off+n > len(buf) {
		return fmt.Errorf("%w: %s needs %d bytes at offset %d, only %d remain",
			ErrMalformed, field, n, off, len(buf)-off)
	}
	return nil
}

// parseRecord walks the concatenated measurement blocks.
func parseRecord(record []byte) ([]Block, error) {
	var blocks []Block
	for off := 0; off < len(record); {
		if err := needs(record, off, blockHeaderSize, "measurement block header"); err != nil {
			return nil, err
		}
		start := off
		index := record[off]
		spec := record[off+1]
		size := int(binary.LittleEndian.Uint16(record[off+2 : off+4]))
		off += blockHeaderSize

		if err := needs(record, off, size, "measurement block body"); err != nil {
			return nil, err
		}
		body := record[off : off+size]
		off += size

		if spec&measurementSpecDMTF == 0 {
			return nil, fmt.Errorf("%w: block %d uses MeasurementSpecification 0x%02X, only DMTF is supported",
				ErrMalformed, index, spec)
		}

		block := Block{
			Index:         int(index),
			Specification: spec,
			Value:         body,
			Raw:           record[start:off],
		}
		if err := decodeDMTF(&block, body); err != nil {
			return nil, err
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

// decodeDMTF unwraps the DMTF measurement header inside a block body.
func decodeDMTF(block *Block, body []byte) error {
	if len(body) < dmtfHeaderSize {
		return fmt.Errorf("%w: block %d body is shorter than the DMTF header", ErrMalformed, block.Index)
	}
	valueSize := int(binary.LittleEndian.Uint16(body[1:3]))
	if dmtfHeaderSize+valueSize != len(body) {
		return fmt.Errorf("%w: block %d declares a %d byte DMTF value inside a %d byte body",
			ErrMalformed, block.Index, valueSize, len(body))
	}
	block.DMTFValueType = body[0]
	block.DMTFValueRepresented = true
	block.Value = body[dmtfHeaderSize:]
	return nil
}
