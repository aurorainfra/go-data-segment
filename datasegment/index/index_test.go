package index

import (
	"testing"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HELPER METHODS

type Node = merkletree.Node

func makeValidEntry(offset, rawSize uint64) *SegmentDesc {
	sd := &SegmentDesc{
		CommDs:              Node{},
		Offset:              offset,
		Height:              pieceSize2Height(rawSize),
		RawSize:             rawSize,
		Multicodec:          MulticodecRaw,
		MulticodecDependent: Node{},
		ACLType:             0,
		ACLData:             0,
	}
	return sd.WithUpdatedChecksum()
}

func invalidEntry1() *SegmentDesc {
	entry := makeValidEntry(123, 127*4)
	entry.Multicodec = 0x9999 // invalid multicodec
	return entry.WithUpdatedChecksum()
}

func invalidEntry2() *SegmentDesc {
	entry := makeValidEntry(311, 127*6)
	entry.Multicodec = 0x8888 // invalid multicodec
	return entry.WithUpdatedChecksum()
}

// makes an index with entries that may be invalid in some way (e.g., alignment)
// but have validPos v2 format fields and checksums for serialization testing
func invalidIndex() IndexData {
	e1 := invalidEntry1()
	e2 := invalidEntry2()
	return IndexData{
		Entries:  []*SegmentDesc{e1, e2},
		validPos: []bool{true, true},
	}
}

func validIndex(t *testing.T) IndexData {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}
	entry1 := NewDataSegmentIndexEntry(&comm1, 128, 256)
	entry2 := NewDataSegmentIndexEntry(&comm2, 128<<5, 128<<4)
	index, err3 := MakeIndex([]*SegmentDesc{entry1, entry2})
	assert.Nil(t, err3)
	return *index
}

func TestValidateEntry(t *testing.T) {
	tests := []struct {
		name string
		sd   *SegmentDesc
		err  string
	}{
		{name: "valid-small", sd: makeValidEntry(0, 127*2)},
		{name: "valid-large", sd: makeValidEntry(128, 127*16)},
		{
			name: "invalid-checksum",
			sd: func() *SegmentDesc {
				sd := makeValidEntry(64, 127*4)
				sd.Checksum = [ChecksumSize]byte{}
				return sd
			}(),
			err: "checksum",
		},
		{
			name: "invalid-multicodec",
			sd: func() *SegmentDesc {
				sd := makeValidEntry(96, 127*8)
				sd.Multicodec = 0x9999
				return sd.WithUpdatedChecksum()
			}(),
			err: "multicodec",
		},
		{
			name: "invalid-rawsize",
			sd: func() *SegmentDesc {
				sd := makeValidEntry(0, 127*2)
				sd.RawSize = sd.Size() + 1
				return sd.WithUpdatedChecksum()
			}(),
			err: "rawSize",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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
	assertSegmentsEqual(t, index.ListPieces(), decoded.ListPieces())
}

// PRIVATE METHODS
func TestIndexSerialization(t *testing.T) {
	index := invalidIndex()
	assert.Equal(t, 2, index.NumPieces())
	// v2: each entry is 256 bytes (4 nodes * 32 bytes) instead of 128 bytes (2 nodes * 32 bytes)
	assert.Equal(t, uint64(2*EntrySize), index.IndexSize())
	encoded, err := index.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, encoded)
	var decoded IndexData
	err = decoded.UnmarshalBinary(encoded)
	assert.NoError(t, err)
	assert.NotNil(t, decoded)
	assert.Equal(t, index.NumPieces(), decoded.NumPieces())
	assert.Equal(t, index.IndexSize(), decoded.IndexSize())
	assertSegmentsEqual(t, index.ListPieces(), decoded.ListPieces())
}

func TestIndexLargeSizes(t *testing.T) {
	idx := validIndex(t)
	// Convert pointer slice to value slice for MakeIndex
	entries := make([]*SegmentDesc, len(idx.Entries))
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
	assertSegmentsEqual(t, index.ListPieces(), decoded.ListPieces())
}

func TestNegativeIndexCreation(t *testing.T) {
	// Nil
	index, err := MakeIndex(nil)
	assert.Error(t, err)
	assert.Nil(t, index)
}

func MakeIndex(entries []*SegmentDesc) (*IndexData, error) {
	index := &IndexData{}
	if err := index.InitFromPieces(entries); err != nil {
		return nil, err
	}
	return index, nil
}

func assertSegmentsEqual(t *testing.T, exp, act []*SegmentDesc) {
	require.Equal(t, len(exp), len(act))
	for i := range exp {
		if exp[i] == nil || act[i] == nil {
			assert.Equal(t, exp[i], act[i])
			continue
		}
		assert.Equal(t, exp[i].SerializeFr32(), act[i].SerializeFr32())
	}
}
