package index

import (
	"fmt"
	"testing"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/stretchr/testify/assert"
)

// HELPER METHODS

type Node = merkletree.Node

func invalidEntry1() SegmentDescV2 {
	// Create an entry with invalid Multicodec (not Raw or CAR) to make it fail validation
	// but with correct format and checksum for serialization testing
	entry := SegmentDescV2{
		CommDs:              Node{},
		Offset:              123,
		Size:                12222,
		RawSize:             12222,  // Set RawSize for v2
		Multicodec:          0x9999, // Invalid multicodec (not Raw or CAR)
		MulticodecDependent: Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [7]byte{},
		Checksum:            [ChecksumSize]byte{},
	}
	// Compute correct checksum (with invalid multicodec)
	entry.Checksum = entry.computeChecksum()
	return entry
}
func invalidEntry2() SegmentDescV2 {
	// Create an entry with invalid Multicodec (not Raw or CAR) to make it fail validation
	// but with correct format and checksum for serialization testing
	entry := SegmentDescV2{
		CommDs:              Node{},
		Offset:              311,
		Size:                22221,
		RawSize:             22221,  // Set RawSize for v2
		Multicodec:          0x8888, // Invalid multicodec (not Raw or CAR)
		MulticodecDependent: Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [7]byte{},
		Checksum:            [ChecksumSize]byte{},
	}
	// Compute correct checksum (with invalid multicodec)
	entry.Checksum = entry.computeChecksum()
	return entry
}

// makes an index with entries that may be invalid in some way (e.g., alignment)
// but have validPos v2 format fields and checksums for serialization testing
func invalidIndex() IndexData {
	e1 := invalidEntry1()
	e2 := invalidEntry2()
	index := IndexData{
		Entries: []*SegmentDescV2{&e1, &e2},
	}
	return index
}

func validIndex(t *testing.T) IndexData {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}
	entry1 := NewDataSegmentIndexEntry(&comm1, 128, 256)
	entry2 := NewDataSegmentIndexEntry(&comm2, 128<<5, 128<<4)
	index, err3 := MakeIndex([]*SegmentDescV2{entry1, entry2})
	assert.Nil(t, err3)
	return *index
}

func TestValidateEntry(t *testing.T) {
	tests := []struct {
		sd  SegmentDescV2
		err string
	}{
		{sd: SegmentDescV2{Offset: 0, Size: 0, RawSize: 0, Multicodec: MulticodecRaw}.withUpdatedChecksum()},
		{sd: SegmentDescV2{Offset: 128, Size: 128 * 3249, RawSize: 128 * 3249, Multicodec: MulticodecRaw}.withUpdatedChecksum()},
		{sd: SegmentDescV2{Offset: 128 * 323221, Size: 128 * 3249, RawSize: 128 * 3249, Multicodec: MulticodecRaw}.withUpdatedChecksum()},
		// v2: flexible alignment, so offset/size alignment checks are removed
		// These test cases now pass validation (no alignment errors)
		{sd: SegmentDescV2{Offset: 128*323221 + 1, Size: 128 * 3249, RawSize: 128 * 3249, Multicodec: MulticodecRaw}.withUpdatedChecksum()},
		{sd: SegmentDescV2{Offset: 128 * 323221, Size: 128*3249 + 1, RawSize: 128*3249 + 1, Multicodec: MulticodecRaw}.withUpdatedChecksum()},
		{sd: SegmentDescV2{Offset: 128 * 323221, Size: 128 * 3249, RawSize: 128 * 3249, Multicodec: MulticodecRaw}, err: "checksum"},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("testcase-%d", i), func(t *testing.T) {
			err := tc.sd.Validate()
			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrValidation)
				assert.ErrorContains(t, err, tc.err)
			}
		})
	}
}

// PUBLIC METHODS
func TestIndexSerializationValidation(t *testing.T) {
	index := validIndex(t)
	encoded, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, encoded)
	var decoded IndexData
	err = decoded.UnmarshalBinary(encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	assert.Equal(t, index, decoded)
}

// PRIVATE METHODS
func TestIndexSerialization(t *testing.T) {
	index := invalidIndex()
	assert.Equal(t, 2, index.NumEntries())
	// v2: each entry is 256 bytes (4 nodes * 32 bytes) instead of 128 bytes (2 nodes * 32 bytes)
	assert.Equal(t, uint64(2*EntrySizeV2), index.IndexSize())
	encoded, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, encoded)
	var decoded IndexData
	err = decoded.UnmarshalBinary(encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	assert.Equal(t, index.NumEntries(), decoded.NumEntries())
	assert.Equal(t, index.IndexSize(), decoded.IndexSize())
	assert.Equal(t, index.Entry(0), decoded.Entry(0))
	assert.Equal(t, index.Entry(1), decoded.Entry(1))
	assert.Equal(t, index, decoded)
}

func TestIndexLargeSizes(t *testing.T) {
	idx := validIndex(t)
	// Convert pointer slice to value slice for MakeIndex
	entries := make([]*SegmentDescV2, len(idx.Entries))
	for i, e := range idx.Entries {
		if e != nil {
			entries[i] = e
		}
	}
	MakeIndex(entries)
}

func TestSegmentEntryValidateFail(t *testing.T) {
	en := invalidEntry1()
	err := en.Validate()
	assert.ErrorIs(t, err, ErrValidation)
}

func TestIndexInvalidEntries(t *testing.T) {
	index := invalidIndex()
	b, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotEmpty(t, b)
	var decoded IndexData
	err = decoded.UnmarshalBinary(b)
	assert.NoError(t, err)
	assert.Equal(t, index, decoded)
	entries1 := index.ListEntries()
	entries2 := decoded.ListEntries()
	assert.Equal(t, entries1, entries2)
}

func TestNegativeIndexCreation(t *testing.T) {
	// Nil
	index, err := MakeIndex(nil)
	assert.Error(t, err)
	assert.Nil(t, index)
}

func MakeIndex(entries []*SegmentDescV2) (*IndexData, error) {
	index := IndexData{
		Entries: entries,
	}
	return &index, nil
}
