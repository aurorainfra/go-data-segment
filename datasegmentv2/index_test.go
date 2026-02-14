package datasegmentv2

import (
	"encoding"
	"testing"

	"github.com/filecoin-project/go-data-segment/fr32"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create test entries
func makeTestEntry(t *testing.T, commP *fr32.Fr32, offset, rawSize uint64) *SegmentDesc {
	entry := NewDataSegmentIndexEntry(commP, offset, rawSize)
	entry = entry.WithUpdatedChecksum()
	return entry
}

func makeTestIndex(t *testing.T, entries []*SegmentDesc) *IndexDataV2 {
	index := &IndexDataV2{
		entries,
	}
	return index
}

func TestInitFromPieces(t *testing.T) {
	// Create test entries
	comm1 := fr32.Fr32{1, 2, 3}
	comm2 := fr32.Fr32{4, 5, 6}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)

	entries := []*SegmentDesc{entry1, entry2}
	index := makeTestIndex(t, entries)

	assert.Equal(t, 2, index.NumPieces())
	assert.Equal(t, entry1, index.Entry(0))
	assert.Equal(t, entry2, index.Entry(1))
}

func TestNumPieces(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}
	comm3 := fr32.Fr32{3}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)
	entry3 := makeTestEntry(t, &comm3, 1536, 256)

	entries := []*SegmentDesc{entry1, entry2, entry3}
	index := makeTestIndex(t, entries)

	assert.Equal(t, 3, index.NumPieces())
}

func TestEntry(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)

	entries := []*SegmentDesc{entry1, entry2}
	index := makeTestIndex(t, entries)

	// Test valid indices
	assert.Equal(t, entry1, index.Entry(0))
	assert.Equal(t, entry2, index.Entry(1))

	// Test invalid indices
	assert.Nil(t, index.Entry(-1))
	assert.Nil(t, index.Entry(2))
	assert.Nil(t, index.Entry(100))
}

func TestSearch(t *testing.T) {
	comm1 := fr32.Fr32{1, 2, 3, 4}
	comm2 := fr32.Fr32{5, 6, 7, 8}
	comm3 := fr32.Fr32{9, 10, 11, 12}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)
	entry3 := makeTestEntry(t, &comm3, 1536, 256)

	entries := []*SegmentDesc{entry1, entry2, entry3}
	index := makeTestIndex(t, entries)

	// Convert CommDs to CIDs for searching
	cid1, err := commcid.PieceCommitmentV1ToCID(entry1.CommDs[:])
	require.NoError(t, err)

	cid2, err := commcid.PieceCommitmentV1ToCID(entry2.CommDs[:])
	require.NoError(t, err)

	cid3, err := commcid.PieceCommitmentV1ToCID(entry3.CommDs[:])
	require.NoError(t, err)

	// Test searching for existing entries
	assert.Equal(t, 0, index.Search(cid1))
	assert.Equal(t, 1, index.Search(cid2))
	assert.Equal(t, 2, index.Search(cid3))

	// Test searching for non-existent entry
	nonExistentComm := fr32.Fr32{99, 98, 97, 96}
	nonExistentCID, err := commcid.PieceCommitmentV1ToCID(nonExistentComm[:])
	require.NoError(t, err)
	assert.Equal(t, -1, index.Search(nonExistentCID))
}

func TestListPieces(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}
	comm3 := fr32.Fr32{3}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)
	entry3 := makeTestEntry(t, &comm3, 1536, 256)

	entries := []*SegmentDesc{entry1, entry2, entry3}
	index := makeTestIndex(t, entries)

	listed := index.ListPieces()
	assert.Equal(t, 3, len(listed))
	assert.Equal(t, entry1, listed[0])
	assert.Equal(t, entry2, listed[1])
	assert.Equal(t, entry3, listed[2])
}

func TestListPieces_WithNil(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)

	// Create index with some nil entries
	index := &IndexDataV2{
		Entries: []*SegmentDesc{entry1, nil, entry2, nil},
	}

	listed := index.ListPieces()
	assert.Equal(t, 2, len(listed))
	assert.Equal(t, entry1, listed[0])
	assert.Equal(t, entry2, listed[1])
}

func TestMarshalBinary(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)

	entries := []*SegmentDesc{entry1, entry2}
	index := makeTestIndex(t, entries)

	data, err := index.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, data)

	// Check size: 2 entries * EntrySize (128 bytes)
	expectedSize := 2 * EntrySize
	assert.Equal(t, expectedSize, len(data))
}

func TestUnmarshalBinary(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)

	entries := []*SegmentDesc{entry1, entry2}
	index := makeTestIndex(t, entries)

	// Marshal
	data, err := index.MarshalBinary()
	require.NoError(t, err)

	// Unmarshal
	var decoded IndexDataV2
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, index.NumPieces(), decoded.NumPieces())
	assert.Equal(t, 2, decoded.NumPieces())

	// Compare entries
	decodedEntry1 := decoded.Entry(0)
	decodedEntry2 := decoded.Entry(1)

	require.NotNil(t, decodedEntry1)
	require.NotNil(t, decodedEntry2)

	assert.Equal(t, entry1.CommDs, decodedEntry1.CommDs)
	assert.Equal(t, entry1.Offset, decodedEntry1.Offset)
	assert.Equal(t, entry1.Size, decodedEntry1.Size)
	assert.Equal(t, entry1.RawSize, decodedEntry1.RawSize)

	assert.Equal(t, entry2.CommDs, decodedEntry2.CommDs)
	assert.Equal(t, entry2.Offset, decodedEntry2.Offset)
	assert.Equal(t, entry2.Size, decodedEntry2.Size)
	assert.Equal(t, entry2.RawSize, decodedEntry2.RawSize)
}

func TestUnmarshalBinary_InvalidSize(t *testing.T) {
	var index IndexDataV2

	// Test with data that's not a multiple of EntrySize
	invalidData := make([]byte, EntrySize+1)
	err := index.UnmarshalBinary(invalidData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a multiple of EntrySize")
}

func TestUnmarshalBinary_Empty(t *testing.T) {
	var index IndexDataV2

	// Test with empty data
	emptyData := make([]byte, 0)
	err := index.UnmarshalBinary(emptyData)
	require.NoError(t, err)
	assert.Equal(t, 0, index.NumPieces())
}

func TestIndexSize(t *testing.T) {
	comm1 := fr32.Fr32{1}
	comm2 := fr32.Fr32{2}
	comm3 := fr32.Fr32{3}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 1024, 512)
	entry3 := makeTestEntry(t, &comm3, 1536, 256)

	entries := []*SegmentDesc{entry1, entry2, entry3}
	index := makeTestIndex(t, entries)

	expectedSize := uint64(3) * uint64(EntrySize)
	assert.Equal(t, expectedSize, index.IndexSize())
}

func TestMaxIndexEntriesInDeal(t *testing.T) {
	// Test with small deal size
	smallDeal := abi.PaddedPieceSize(1024)
	maxEntries := MaxIndexEntriesInDeal(smallDeal)
	assert.GreaterOrEqual(t, maxEntries, uint(NodesPerEntry))

	// Test with medium deal size
	mediumDeal := abi.PaddedPieceSize(1 << 20) // 1MB
	maxEntries = MaxIndexEntriesInDeal(mediumDeal)
	assert.Greater(t, maxEntries, uint(0))

	// Test with large deal size
	largeDeal := abi.PaddedPieceSize(32 << 30) // 32GB
	maxEntries = MaxIndexEntriesInDeal(largeDeal)
	assert.Greater(t, maxEntries, uint(0))

	// Verify it's always at least NodesPerEntry
	assert.GreaterOrEqual(t, maxEntries, uint(NodesPerEntry))
}

func TestIndexSerializationRoundTrip(t *testing.T) {
	// Create multiple entries with different properties
	comm1 := fr32.Fr32{1, 2, 3, 4, 5}
	comm2 := fr32.Fr32{6, 7, 8, 9, 10}
	comm3 := fr32.Fr32{11, 12, 13, 14, 15}

	entry1 := makeTestEntry(t, &comm1, 0, 1024)
	entry2 := makeTestEntry(t, &comm2, 2048, 512) // Non-consecutive offset
	entry3 := makeTestEntry(t, &comm3, 3000, 777) // Non-power-of-two size

	entries := []*SegmentDesc{entry1, entry2, entry3}
	index := makeTestIndex(t, entries)

	// Marshal
	data, err := index.MarshalBinary()
	require.NoError(t, err)

	// Unmarshal
	var decoded IndexDataV2
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify all entries match
	assert.Equal(t, index.NumPieces(), decoded.NumPieces())

	for i := 0; i < index.NumPieces(); i++ {
		original := index.Entry(i)
		decodedEntry := decoded.Entry(i)

		require.NotNil(t, original)
		require.NotNil(t, decodedEntry)

		assert.Equal(t, original.CommDs, decodedEntry.CommDs)
		assert.Equal(t, original.Offset, decodedEntry.Offset)
		assert.Equal(t, original.Size, decodedEntry.Size)
		assert.Equal(t, original.RawSize, decodedEntry.RawSize)
		assert.Equal(t, original.Checksum, decodedEntry.Checksum)
	}
}

func TestSearch_NotFound(t *testing.T) {
	comm1 := fr32.Fr32{1}
	entry1 := makeTestEntry(t, &comm1, 0, 1024)

	entries := []*SegmentDesc{entry1}
	index := makeTestIndex(t, entries)

	// Search for a CID that doesn't exist
	nonExistentComm := fr32.Fr32{99, 98, 97}
	nonExistentCID, err := commcid.PieceCommitmentV1ToCID(nonExistentComm[:])
	require.NoError(t, err)

	result := index.Search(nonExistentCID)
	assert.Equal(t, -1, result)
}

func TestSearch_InvalidCID(t *testing.T) {
	comm1 := fr32.Fr32{1}
	entry1 := makeTestEntry(t, &comm1, 0, 1024)

	entries := []*SegmentDesc{entry1}
	index := makeTestIndex(t, entries)

	// Create an invalid CID (not a piece commitment CID)
	invalidCID := cid.Undef
	result := index.Search(invalidCID)
	assert.Equal(t, -1, result)
}

func TestMarshalBinary_WithNilEntries(t *testing.T) {
	comm1 := fr32.Fr32{1}
	entry1 := makeTestEntry(t, &comm1, 0, 1024)

	// Create index with nil entries
	index := &IndexDataV2{
		Entries: []*SegmentDesc{entry1, nil, nil},
	}

	data, err := index.MarshalBinary()
	require.NoError(t, err)

	// Should still marshal successfully, nil entries are handled
	assert.Equal(t, 3*EntrySize, len(data))
}

func TestUnmarshalBinary_MultipleEntries(t *testing.T) {
	// Create index with many entries
	entries := make([]*SegmentDesc, 10)
	for i := 0; i < 10; i++ {
		comm := fr32.Fr32{byte(i), byte(i + 1), byte(i + 2)}
		entries[i] = makeTestEntry(t, &comm, uint64(i*1024), 1024)
	}

	index := makeTestIndex(t, entries)

	// Marshal and unmarshal
	data, err := index.MarshalBinary()
	require.NoError(t, err)

	var decoded IndexDataV2
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, 10, decoded.NumPieces())

	// Verify all entries
	for i := 0; i < 10; i++ {
		original := index.Entry(i)
		decodedEntry := decoded.Entry(i)

		require.NotNil(t, original)
		require.NotNil(t, decodedEntry)

		assert.Equal(t, original.CommDs, decodedEntry.CommDs)
		assert.Equal(t, original.Offset, decodedEntry.Offset)
	}
}

func TestIndexDataV2_ImplementsPieceIndex(t *testing.T) {
	// Verify that IndexDataV2 implements the PieceIndex interface
	var _ PieceIndex = (*IndexDataV2)(nil)

	// This test will fail at compile time if IndexDataV2 doesn't implement PieceIndex
	// So if we get here, the implementation is correct
}

func TestIndexDataV2_ImplementsBinaryUnmarshaler(t *testing.T) {
	// Verify that IndexDataV2 implements encoding.BinaryUnmarshaler
	var _ encoding.BinaryUnmarshaler = (*IndexDataV2)(nil)

	// This test will fail at compile time if IndexDataV2 doesn't implement BinaryUnmarshaler
}
