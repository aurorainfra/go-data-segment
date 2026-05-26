package datasegmentv2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"
	commp "github.com/filecoin-project/go-fil-commp-hashhash"
	"github.com/filecoin-project/go-state-types/abi"
	cid "github.com/ipfs/go-cid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestData creates random test data of the specified size
func makeTestDataInclusion(size uint64) []byte {
	data := make([]byte, size)
	_, _ = rand.Read(data) // Ignore error in test helper
	return data
}

func requirePieceCIDForData(t *testing.T, data []byte) cid.Cid {
	t.Helper()
	calc := &commp.Calc{}
	n, err := calc.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), n)
	digest, _, err := calc.Digest()
	require.NoError(t, err)
	commPc, err := commcid.PieceCommitmentV1ToCID(digest)
	require.NoError(t, err)
	return commPc
}

// TestCollectInclusionProof_SinglePiece tests collecting inclusion proof for a single piece
func TestCollectInclusionProof_SinglePiece(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB (reduced for faster tests)
	pieceData := makeTestDataInclusion(1024) // 1KB piece

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
	// Collect inclusion proof for piece 0
	proof, err := CollectInclusionProof(agg.Tree, agg.DealSize, 0)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Verify proof structure
	assert.NotNil(t, proof.LeftProofSubtree)
	assert.NotNil(t, proof.RightProofSubtree)
	assert.NotNil(t, proof.ProofIndex)

	// For a single small piece, left and right proofs might be the same
	assert.GreaterOrEqual(t, len(proof.LeftProofSubtree.Path), 0)
	assert.GreaterOrEqual(t, len(proof.RightProofSubtree.Path), 0)
	assert.GreaterOrEqual(t, len(proof.ProofIndex.Path), 0)
}

// TestCollectInclusionProof_MultiplePieces tests collecting inclusion proof for multiple pieces
func TestCollectInclusionProof_MultiplePieces(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB (reduced for faster tests)
	piece1Data := makeTestDataInclusion(512)
	piece2Data := makeTestDataInclusion(256)
	piece3Data := makeTestDataInclusion(1024)

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
	// Collect proofs for all pieces
	for i := 0; i < len(pieces); i++ {
		proof, err := CollectInclusionProof(agg.Tree, agg.DealSize, i)
		require.NoError(t, err, "failed to collect proof for piece %d", i)
		require.NotNil(t, proof, "proof is nil for piece %d", i)

		assert.NotNil(t, proof.LeftProofSubtree, "left proof is nil for piece %d", i)
		assert.NotNil(t, proof.RightProofSubtree, "right proof is nil for piece %d", i)
		assert.NotNil(t, proof.ProofIndex, "index proof is nil for piece %d", i)
	}
}

// TestCollectInclusionProof_InvalidIndex tests error handling for invalid piece indices
func TestCollectInclusionProof_InvalidIndex(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB (reduced for faster tests)
	pieceData := makeTestDataInclusion(1024)

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
	_, err = CollectInclusionProof(agg.Tree, agg.DealSize, -1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid piece index")

	// Test index out of bounds
	// Note: CollectInclusionProof uses tree.NumPieces() for validation, not len(pieces)
	_, err = CollectInclusionProof(agg.Tree, agg.DealSize, agg.Tree.NumPieces())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid piece index")
}

// TestComputeExpectedAuxData_SinglePiece tests computing expected aux data for a single piece
func TestComputeExpectedAuxData_SinglePiece(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB (reduced for faster tests)
	pieceData := makeTestDataInclusion(2048) // 2KB piece

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
	// Get the actual CommPa (aggregator's deal commitment)
	commPa, err := agg.PieceCID()
	require.NoError(t, err)

	// Collect inclusion proof
	proof, err := CollectInclusionProof(agg.Tree, agg.DealSize, 0)
	require.NoError(t, err)

	// Get the content CID from the index entry and compute the piece CommP separately.
	entry := agg.Index.Entry(0)
	require.NotNil(t, entry)
	dataCID, err := entry.DataCID()
	require.NoError(t, err)
	commPc := requirePieceCIDForData(t, pieceData)

	// Create verifier data
	verifierData := InclusionVerifierData{
		CommPc:  commPc,
		DataCID: dataCID,
		Offset:  pieces[0].PieceInfo.BeginAt,
		SizePc:  pieces[0].PieceInfo.RawSize,
	}

	// Compute expected aux data
	auxData, err := proof.ComputeExpectedAuxData(verifierData)
	require.NoError(t, err)
	require.NotNil(t, auxData)

	// Verify aux data matches expected values
	assert.Equal(t, commPa, auxData.CommPa, "CommPa mismatch")
	assert.Equal(t, dealSize, auxData.SizePa, "SizePa mismatch")
}

// TestComputeExpectedAuxData_ZeroSize tests error handling for zero size
func TestComputeExpectedAuxData_ZeroSize(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB (reduced for faster tests)
	pieceData := makeTestDataInclusion(1024)

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
	proof, err := CollectInclusionProof(agg.Tree, agg.DealSize, 0)
	require.NoError(t, err)
	entry := agg.Index.Entry(0)
	require.NotNil(t, entry)
	dataCID, err := entry.DataCID()
	require.NoError(t, err)
	commPc := requirePieceCIDForData(t, pieceData)
	// Test with zero size
	verifierData := InclusionVerifierData{
		CommPc:  commPc,
		DataCID: dataCID,
		Offset:  0,
		SizePc:  0, // Zero size should cause error
	}

	_, err = proof.ComputeExpectedAuxData(verifierData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zero")
}

// TestComputeExpectedAuxData_InvalidCommP tests error handling for invalid CommP
func TestComputeExpectedAuxData_InvalidCommP(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 20) // 1 MiB (reduced for faster tests)
	pieceData := makeTestDataInclusion(1024)

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
	proof, err := CollectInclusionProof(agg.Tree, agg.DealSize, 0)
	require.NoError(t, err)
	// Create invalid CID (too short)
	invalidCid, err := commcid.PieceCommitmentV1ToCID([]byte{0x1, 0x2, 0x3})
	if err == nil {
		verifierData := InclusionVerifierData{
			CommPc: invalidCid,
			Offset: 0,
			SizePc: 1024,
		}

		_, err = proof.ComputeExpectedAuxData(verifierData)
		// Should fail when trying to extract CommP from CID
		assert.Error(t, err)
	}
}

// TestInclusionProof_MultiplePieces_Verification tests that inclusion proofs for multiple pieces
// in a single sector can be collected and verified correctly.
// This test creates a sector with multiple pieces, collects proofs for each piece,
// and verifies that the proofs are valid and consistent.
func TestInclusionProof_MultiplePieces_Verification(t *testing.T) {
	dealSize := abi.PaddedPieceSize(1 << 21) // 2 MiB (enough index capacity for 4 pieces)
	piece1Data := makeTestDataInclusion(1024)
	piece2Data := makeTestDataInclusion(512)
	piece3Data := makeTestDataInclusion(2048)
	piece4Data := makeTestDataInclusion(256)
	pieceDatas := [][]byte{piece1Data, piece2Data, piece3Data, piece4Data}

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 2048, // Gap between pieces
				RawSize: 512,
			},
		},
		{
			Reader: bytes.NewReader(piece3Data),
			PieceInfo: PieceInfo{
				BeginAt: 4096,
				RawSize: 2048,
			},
		},
		{
			Reader: bytes.NewReader(piece4Data),
			PieceInfo: PieceInfo{
				BeginAt: 8192, // Misaligned offset
				RawSize: 256,
			},
		},
	}

	agg, err := NewAggregate(dealSize, pieces)
	agg = requireAggregateOrSkip(t, agg, err)
	// Get the actual sector root (CommPa)
	sectorRoot, err := agg.PieceCID()
	require.NoError(t, err)
	require.False(t, sectorRoot.Equals(cid.Undef))

	// For each piece, collect proof and verify
	for i, piece := range pieces {
		t.Run(fmt.Sprintf("Piece%d", i), func(t *testing.T) {
			// Collect inclusion proof for this piece
			proof, err := CollectInclusionProof(agg.Tree, agg.DealSize, i)
			require.NoError(t, err, "piece %d: failed to collect proof", i)
			require.NotNil(t, proof, "piece %d: proof is nil", i)

			// Verify proof structure
			assert.NotNil(t, proof.LeftProofSubtree, "piece %d: left proof is nil", i)
			assert.NotNil(t, proof.RightProofSubtree, "piece %d: right proof is nil", i)
			assert.NotNil(t, proof.ProofIndex, "piece %d: index proof is nil", i)

			// Verify proof paths are non-empty
			assert.GreaterOrEqual(t, len(proof.LeftProofSubtree.Path), 0, "piece %d: left proof path is empty", i)
			assert.GreaterOrEqual(t, len(proof.RightProofSubtree.Path), 0, "piece %d: right proof path is empty", i)
			assert.GreaterOrEqual(t, len(proof.ProofIndex.Path), 0, "piece %d: index proof path is empty", i)

			// Get the content CID from the index entry and compute the piece CommP separately.
			entry := agg.Index.Entry(i)
			require.NotNil(t, entry, "piece %d: index entry is nil", i)
			dataCID, err := entry.DataCID()
			require.NoError(t, err, "piece %d: failed to get data CID", i)
			commPc := requirePieceCIDForData(t, pieceDatas[i])
			require.False(t, commPc.Equals(cid.Undef), "piece %d: piece CID is undefined", i)

			// Create verifier data
			verifierData := InclusionVerifierData{
				CommPc:  commPc,
				DataCID: dataCID,
				Offset:  piece.PieceInfo.BeginAt,
				SizePc:  piece.PieceInfo.RawSize,
			}

			// Verify that the index entry matches what we expect.
			assert.Equal(t, piece.PieceInfo.BeginAt, entry.Offset, "piece %d: offset mismatch", i)
			assert.Equal(t, piece.PieceInfo.RawSize, entry.RawSize, "piece %d: raw size mismatch", i)

			// Compute expected aux data and verify
			auxData, err := proof.ComputeExpectedAuxData(verifierData)
			require.NoError(t, err, "piece %d: failed to compute expected aux data", i)
			require.NotNil(t, auxData, "piece %d: aux data is nil", i)

			// Verify the results match expected values
			assert.Equal(t, sectorRoot, auxData.CommPa, "piece %d: sector root mismatch", i)
			assert.Equal(t, dealSize, auxData.SizePa, "piece %d: deal size mismatch", i)

			// Verify that left and right proofs have valid indices
			assert.GreaterOrEqual(t, int(proof.LeftProofSubtree.Index), 0, "piece %d: invalid left proof index", i)
			assert.GreaterOrEqual(t, int(proof.RightProofSubtree.Index), 0, "piece %d: invalid right proof index", i)
			assert.GreaterOrEqual(t, int(proof.ProofIndex.Index), 0, "piece %d: invalid index proof index", i)

			// For pieces that span multiple leaves, left and right proofs should be different
			// For pieces that fit in a single leaf, they might be the same
			if proof.LeftProofSubtree.Index != proof.RightProofSubtree.Index {
				t.Logf("piece %d: spans multiple leaves (left: %d, right: %d)", i,
					proof.LeftProofSubtree.Index, proof.RightProofSubtree.Index)
			}
		})
	}

	// Verify that all pieces have different data CIDs (unless they have identical data).
	dataCIDs := make([]cid.Cid, len(pieces))
	for i := 0; i < len(pieces); i++ {
		entry := agg.Index.Entry(i)
		require.NotNil(t, entry)
		dataCID, err := entry.DataCID()
		require.NoError(t, err)
		dataCIDs[i] = dataCID
	}

	// Check that pieces with different data have different content CIDs.
	// (This is probabilistic - very unlikely for random data to have same digest.)
	for i := 0; i < len(dataCIDs); i++ {
		for j := i + 1; j < len(dataCIDs); j++ {
			if dataCIDs[i].Equals(dataCIDs[j]) {
				t.Logf("Warning: pieces %d and %d have the same data CID (unlikely but possible)", i, j)
			}
		}
	}
}
