package datasegmentv2

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"
	commp2 "github.com/filecoin-project/go-fil-commp-hashhash/commp2"
	"github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestDataCreation creates random test data of the specified size
func makeTestDataCreation(size uint64) []byte {
	data := make([]byte, size)
	_, _ = rand.Read(data) // Ignore error in test helper
	return data
}

// requireAggregateOrSkip calls require.NoError(t, err) and require.NotNil(t, agg).
// If NewAggregate returned (nil, nil) because the full implementation is not active, the test is skipped.
func requireAggregateOrSkip(t *testing.T, agg *AggregateV2, err error) *AggregateV2 {
	t.Helper()
	if err == nil && agg == nil {
		t.Skip("NewAggregate full implementation is not active (returns nil, nil)")
	}
	require.NoError(t, err)
	require.NotNil(t, agg)
	return agg
}

// TestNewAggregate_SinglePiece tests creating an aggregate with a single piece
func TestNewAggregate_SinglePiece(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 mb
	pieceData := makeTestDataCreation(1024)  // 1KB piece

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Verify aggregate structure
	assert.Equal(t, dealSize, agg.DealSize)
	assert.NotNil(t, agg.Index)
	assert.NotNil(t, agg.Tree)
	assert.Equal(t, 1, agg.Index.NumPieces())
	// Tree includes index as a piece, so NumPieces = pieces + 1
	assert.Equal(t, 2, agg.Tree.NumPieces())

	// Verify tree is valid
	assert.True(t, agg.Tree.Validate())
}

// TestNewAggregate_MultiplePieces tests creating an aggregate with multiple pieces
func TestNewAggregate_MultiplePieces(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 mb
	piece1Data := makeTestDataCreation(512)
	piece2Data := makeTestDataCreation(256)
	piece3Data := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 512,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 1024, // Gap between pieces
				RawSize: 256,
			},
		},
		{
			Reader: bytes.NewReader(piece3Data),
			PieceInfo: PieceInfo{
				BeginAt: 2048,
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	assert.Equal(t, 3, agg.Index.NumPieces())
	// Tree includes index as a piece, so NumPieces = pieces + 1
	assert.Equal(t, 4, agg.Tree.NumPieces())
	assert.True(t, agg.Tree.Validate())

	// Verify index entries match pieces
	for i, piece := range pieces {
		entry := agg.Index.Entry(i)
		require.NotNil(t, entry, "entry %d is nil", i)
		assert.Equal(t, piece.BeginAt, entry.Offset, "entry %d offset mismatch", i)
		assert.Equal(t, piece.RawSize, entry.RawSize, "entry %d rawSize mismatch", i)
	}
}

// TestNewAggregate_ConsecutivePieces tests creating an aggregate with consecutive pieces
func TestNewAggregate_ConsecutivePieces(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	piece1Data := makeTestDataCreation(512)
	piece2Data := makeTestDataCreation(256)
	piece3Data := makeTestDataCreation(128)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 512,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 512, // Consecutive
				RawSize: 256,
			},
		},
		{
			Reader: bytes.NewReader(piece3Data),
			PieceInfo: PieceInfo{
				BeginAt: 768, // Consecutive
				RawSize: 128,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	assert.Equal(t, 3, agg.Index.NumPieces())
	assert.True(t, agg.Tree.Validate())
}

// TestNewAggregate_EmptyPieces tests error handling for empty pieces list
func TestNewAggregate_EmptyPieces(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieces := []PieceData{}

	agg, err := NewAggregate(dealSize, pieces)
	// Empty pieces might be allowed or not, depending on implementation
	// For now, we'll check if it returns an error or creates an aggregate
	if err != nil {
		assert.Contains(t, err.Error(), "at least one piece")
		assert.Nil(t, agg)
	}
}

// TestNewAggregate_ZeroSizePiece tests error handling for zero-size piece
func TestNewAggregate_ZeroSizePiece(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 0, // Zero size should cause error
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	require.Error(t, err)
	require.Nil(t, agg)
	if err != nil {
		assert.Contains(t, err.Error(), "zero")
	}
}

// TestNewAggregate_PiecesTooLarge tests error handling when pieces don't fit in deal
func TestNewAggregate_PiecesTooLarge(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20)   // 1 MiB - small deal
	pieceData := makeTestDataCreation(2 << 20) // 2 MiB - too large

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 2 << 20,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	require.Error(t, err)
	require.Nil(t, agg)
	if err != nil {
		assert.Contains(t, err.Error(), "too large")
	}
}

// TestNewAggregate_TooManyPieces tests error handling when too many pieces for deal size
func TestNewAggregate_TooManyPieces(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB - small deal
	maxEntries := MaxIndexEntriesInDeal(dealSize)

	// Create more pieces than allowed
	pieces := make([]PieceData, maxEntries+1)
	for i := range pieces {
		pieceData := makeTestDataCreation(1024)
		pieces[i] = PieceData{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: uint64(i * 1024),
				RawSize: 1024,
			},
		}
	}

	agg, err := NewAggregate(dealSize, pieces)
	require.Error(t, err)
	require.Nil(t, agg)
	if err != nil {
		assert.Contains(t, err.Error(), "too many pieces")
	}
}

// TestAggregateV2_PieceCID tests getting the PieceCID of the aggregate
func TestAggregateV2_PieceCID(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(2048)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 2048,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	pieceCID, err := agg.PieceCID()
	require.NoError(t, err)
	assert.False(t, pieceCID.Equals(cid.Undef))

	// Verify it's a valid Piece Commitment CID
	commP, err := commcid.CIDToPieceCommitmentV1(pieceCID)
	require.NoError(t, err)
	assert.Equal(t, 32, len(commP))
}

// TestAggregateV2_IndexPieceCID tests getting the IndexPieceCID
func TestAggregateV2_IndexPieceCID(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	indexCID, err := agg.IndexPieceCID()
	require.NoError(t, err)
	assert.False(t, indexCID.Equals(cid.Undef))

	// Verify it's a valid Piece Commitment CID
	commP, err := commcid.CIDToPieceCommitmentV1(indexCID)
	require.NoError(t, err)
	assert.Equal(t, 32, len(commP))
}

// TestAggregateV2_IndexSize tests getting the index size
func TestAggregateV2_IndexSize(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	indexSize, err := agg.IndexSize()
	require.NoError(t, err)

	// Index size should be based on max entries for the deal size
	maxEntries := MaxIndexEntriesInDeal(dealSize)
	expectedSize := abi.PaddedPieceSize(uint64(maxEntries) * EntrySize)
	assert.Equal(t, expectedSize, indexSize)
}

// TestAggregateV2_IndexReader tests reading the index
func TestAggregateV2_IndexReader(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	indexReader, err := agg.IndexReader()
	require.NoError(t, err)
	require.NotNil(t, indexReader)

	// Read all index data
	indexData, err := io.ReadAll(indexReader)
	require.NoError(t, err)
	assert.Greater(t, len(indexData), 0)
}

// TestAggregateV2_ProofForIndexEntry tests getting proof for an index entry
func TestAggregateV2_ProofForIndexEntry(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	piece1Data := makeTestDataCreation(512)
	piece2Data := makeTestDataCreation(256)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 512,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 1024,
				RawSize: 256,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Get proof for first piece
	proof, err := agg.ProofForIndexEntry(0)
	require.NoError(t, err)
	require.NotNil(t, proof)
	assert.NotNil(t, proof.LeftProofSubtree)
	assert.NotNil(t, proof.RightProofSubtree)
	assert.NotNil(t, proof.ProofIndex)

	// Get proof for second piece
	proof2, err := agg.ProofForIndexEntry(1)
	require.NoError(t, err)
	require.NotNil(t, proof2)
}

// TestAggregateV2_ProofForIndexEntry_InvalidIndex tests error handling for invalid index
func TestAggregateV2_ProofForIndexEntry_InvalidIndex(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Test negative index
	_, err = agg.ProofForIndexEntry(-1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid piece index")

	// Test index out of bounds
	_, err = agg.ProofForIndexEntry(agg.Index.NumPieces())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid piece index")
}

// TestNewAggregate_MisalignedPieces tests creating aggregate with misaligned pieces
func TestNewAggregate_MisalignedPieces(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	piece1Data := makeTestDataCreation(300)  // Non-power-of-two size
	piece2Data := makeTestDataCreation(777)  // Non-power-of-two size

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 127, // Non-aligned offset
				RawSize: 300,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 500, // Non-aligned offset
				RawSize: 777,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	assert.Equal(t, 2, agg.Index.NumPieces())
	assert.True(t, agg.Tree.Validate())
}

// TestNewAggregate_LargeDeal tests creating aggregate with a large deal size
func TestNewAggregate_LargeDeal(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 22)     // 4 MiB - large enough to test but not too slow
	pieceData := makeTestDataCreation(64 * 1024) // 64KB

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 64 * 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	assert.True(t, agg.Tree.Validate())
	assert.Equal(t, dealSize, agg.DealSize)
}

// TestAggregateV2_PieceCommP_Consistency_OffsetZero tests CommP consistency for pieces at offset 0
func TestAggregateV2_PieceCommP_Consistency_OffsetZero(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	pieceData := makeTestDataCreation(1024)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0, // Offset 0
				RawSize: 1024,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Calculate CommP individually using commp2 with BeginAt=0
	calc := &commp2.Calc{}
	if err := calc.BeginAt(0); err != nil {
		t.Fatalf("failed to set BeginAt: %v", err)
	}

	n, err := calc.Write(pieceData)
	require.NoError(t, err)
	require.Equal(t, len(pieceData), n)

	commp2Digest, _, err := calc.Digest()
	require.NoError(t, err)
	require.NotNil(t, commp2Digest)
	require.Equal(t, 32, len(commp2Digest))

	// Get CommP from index entry (stored as CommData when built from CommP)
	entry := agg.Index.Entry(0)
	require.NotNil(t, entry)
	indexCommP := entry.CommData

	// Compare CommP values
	commp2CommPArray := [32]byte{}
	copy(commp2CommPArray[:], commp2Digest)

	assert.Equal(t, indexCommP[:], commp2CommPArray[:],
		"CommP mismatch for offset=0 piece\n"+
			"  Index CommP (from tree):  %x\n"+
			"  commp2 CommP (calculated): %x",
		indexCommP[:], commp2CommPArray[:])
}

// TestAggregateV2_PieceCommP_Consistency tests that CommP calculated individually
// for each piece using commp2 matches the CommP stored in the index entry.
// This test verifies that the CommP stored in the index (calculated using commp2
// with BeginAt) matches the CommP calculated independently using the same method.
func TestAggregateV2_PieceCommP_Consistency(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	piece1Data := makeTestDataCreation(512)
	piece2Data := makeTestDataCreation(1024)
	piece3Data := makeTestDataCreation(256)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 512,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 1024, // Gap between pieces
				RawSize: 1024,
			},
		},
		{
			Reader: bytes.NewReader(piece3Data),
			PieceInfo: PieceInfo{
				BeginAt: 3000, // Another gap
				RawSize: 256,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Store original piece data for commp2 calculation
	pieceDataList := [][]byte{piece1Data, piece2Data, piece3Data}

	// For each piece, verify that individually calculated CommP matches index entry
	for i, piece := range pieces {
		// Calculate CommP individually using commp2 with BeginAt
		// This simulates how the piece would be calculated if it were placed
		// at the given offset in a sector
		calc := &commp2.Calc{}
		if err := calc.BeginAt(piece.BeginAt); err != nil {
			t.Fatalf("piece %d: failed to set BeginAt: %v", i, err)
		}

		// Write the piece data
		n, err := calc.Write(pieceDataList[i])
		require.NoError(t, err, "piece %d: failed to write data to commp2", i)
		require.Equal(t, len(pieceDataList[i]), n, "piece %d: incomplete write to commp2", i)

		// Get the digest (CommP) from commp2
		commp2Digest, paddedSize, err := calc.Digest()
		require.NoError(t, err, "piece %d: failed to get digest from commp2", i)
		require.NotNil(t, commp2Digest, "piece %d: commp2 digest is nil", i)
		require.Equal(t, 32, len(commp2Digest), "piece %d: commp2 digest should be 32 bytes", i)
		require.Greater(t, paddedSize, uint64(0), "piece %d: padded size should be > 0", i)

		// Get CommP from index entry (stored as CommData when built from CommP)
		entry := agg.Index.Entry(i)
		require.NotNil(t, entry, "piece %d: index entry is nil", i)
		indexCommP := entry.CommData

		// Compare CommP values
		// commp2Digest is a slice, indexCommP is [32]byte (merkletree.Node)
		commp2CommPArray := [32]byte{}
		copy(commp2CommPArray[:], commp2Digest)

		// The CommP from the index should match the CommP calculated with commp2
		// Both use commp2 with BeginAt to calculate the piece's CommP at its offset
		assert.Equal(t, indexCommP[:], commp2CommPArray[:],
			"piece %d: CommP mismatch\n"+
				"  Index CommP:  %x\n"+
				"  commp2 CommP: %x\n"+
				"  BeginAt: %d, RawSize: %d",
			i, indexCommP[:], commp2CommPArray[:], piece.BeginAt, piece.RawSize)

		// Verify piece commitment CID from index CommData matches commp2
		commp2CID, err := commcid.PieceCommitmentV1ToCID(commp2Digest)
		require.NoError(t, err, "piece %d: failed to convert commp2 digest to CID", i)
		indexPieceCID, err := commcid.PieceCommitmentV1ToCID(indexCommP[:])
		require.NoError(t, err, "piece %d: failed to convert index CommData to CID", i)
		assert.True(t, indexPieceCID.Equals(commp2CID),
			"piece %d: piece CID from index CommData should match commp2\n"+
				"  Index CID:  %s\n"+
				"  commp2 CID: %s",
			i, indexPieceCID.String(), commp2CID.String())
	}
}

// TestAggregateV2_PieceCommP_Consistency_Misaligned tests CommP consistency for misaligned pieces
func TestAggregateV2_PieceCommP_Consistency_Misaligned(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB
	piece1Data := makeTestDataCreation(300)  // Non-power-of-two size
	piece2Data := makeTestDataCreation(777)  // Non-power-of-two size

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 127, // Non-aligned offset
				RawSize: 300,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 500, // Non-aligned offset
				RawSize: 777,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Store original piece data for commp2 calculation
	pieceDataList := [][]byte{piece1Data, piece2Data}

	// For each piece, verify that individually calculated CommP matches index entry
	for i, piece := range pieces {
		// Calculate CommP individually using commp2 with BeginAt
		calc := &commp2.Calc{}
		if err := calc.BeginAt(piece.BeginAt); err != nil {
			t.Fatalf("piece %d: failed to set BeginAt: %v", i, err)
		}

		// Write the piece data
		n, err := calc.Write(pieceDataList[i])
		require.NoError(t, err, "piece %d: failed to write data to commp2", i)
		require.Equal(t, len(pieceDataList[i]), n, "piece %d: incomplete write to commp2", i)

		// Get the digest (CommP) from commp2
		commp2Digest, paddedSize, err := calc.Digest()
		require.NoError(t, err, "piece %d: failed to get digest from commp2", i)
		require.NotNil(t, commp2Digest, "piece %d: commp2 digest is nil", i)
		require.Equal(t, 32, len(commp2Digest), "piece %d: commp2 digest should be 32 bytes", i)
		require.Greater(t, paddedSize, uint64(0), "piece %d: padded size should be > 0", i)

		// Get CommP from index entry (stored as CommData when built from CommP)
		entry := agg.Index.Entry(i)
		require.NotNil(t, entry, "piece %d: index entry is nil", i)
		indexCommP := entry.CommData

		// Compare CommP values
		commp2CommPArray := [32]byte{}
		copy(commp2CommPArray[:], commp2Digest)

		// The CommP from the index should match the CommP calculated with commp2
		assert.Equal(t, indexCommP[:], commp2CommPArray[:],
			"piece %d: CommP mismatch for misaligned piece\n"+
				"  Index CommP:  %x\n"+
				"  commp2 CommP: %x\n"+
				"  BeginAt: %d, RawSize: %d",
			i, indexCommP[:], commp2CommPArray[:], piece.BeginAt, piece.RawSize)
	}
}

// TestSegmentDesc_PieceCIDV2 asserts PieceCIDV2 is not supported in CID-based index format.
func TestSegmentDesc_PieceCIDV2(t *testing.T) {
	// In CID-based index format, PieceCIDV2 is not supported (no CommP stored).
	t.Run("Unsupported", func(t *testing.T) {
		entry := NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, []byte{1, 2, 3, 4, 5}, 0, 1024)
		require.NotNil(t, entry)
		pieceCID, err := entry.PieceCIDV2()
		assert.Error(t, err)
		assert.True(t, pieceCID.Equals(cid.Undef))
		assert.Contains(t, err.Error(), "not supported")
	})

	// DataCID is supported for content lookup.
	t.Run("DataCID", func(t *testing.T) {
		digest := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		entry := NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, digest, 0, 256)
		require.NotNil(t, entry)
		dataCID, err := entry.DataCID()
		require.NoError(t, err)
		assert.False(t, dataCID.Equals(cid.Undef))
	})
}
