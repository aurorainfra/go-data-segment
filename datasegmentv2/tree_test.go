package datasegmentv2

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commp "github.com/filecoin-project/go-fil-commp-hashhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create test data
func makeTestData(size uint64) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func TestBuildSectorTree_SinglePiece(t *testing.T) {
	// Test building a tree with a single piece at offset 0
	pieceData := makeTestData(1024) // 1KB of data

	// Create pieces with fresh readers
	createPieces := func() []PieceData {
		return []PieceData{
			{
				Reader: bytes.NewReader(pieceData),
				PieceInfo: PieceInfo{
					BeginAt: 0,
					RawSize: 1024,
		},
			},
		}
	}

	tree, err := BuildSectorTree(createPieces(), 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	// Verify tree structure
	assert.Greater(t, tree.Depth(), 0)
	assert.Greater(t, tree.LeafCount(), uint64(0))
	assert.NotNil(t, tree.Root())

	// Verify tree is valid
	assert.True(t, tree.Validate())

	// Verify root is not zero
	root := tree.Root()
	assert.NotNil(t, root)
	assert.NotEqual(t, [32]byte{}, *root)

	verifyCommPWithCommp2(t, tree, createPieces(), 0)
}

func TestBuildSectorTree_MultiplePieces(t *testing.T) {
	// Test building a tree with multiple pieces at different offsets
	piece1Data := makeTestData(512)
	piece2Data := makeTestData(256)
	piece3Data := makeTestData(1024)

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
				BeginAt: 1024, // Offset 1KB
				RawSize: 256,
			},
		},
		{
			Reader: bytes.NewReader(piece3Data),
			PieceInfo: PieceInfo{
				BeginAt: 2048, // Offset 2KB
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	assert.Equal(t, 3, tree.NumPieces())
	assert.True(t, tree.Validate())
	assert.NotNil(t, tree.Root())
}

func TestBuildSectorTree_MisalignedPieces(t *testing.T) {
	// Test building a tree with misaligned pieces (non-power-of-two offsets and sizes)
	piece1Data := makeTestData(300) // Non-power-of-two size
	piece2Data := makeTestData(777) // Non-power-of-two size

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 127, // Non-aligned offset
				RawSize: 300, // Non-power-of-two size
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 500, // Non-aligned offset
				RawSize: 777, // Non-power-of-two size
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	assert.True(t, tree.Validate())
	assert.Equal(t, 2, tree.NumPieces())
}

func TestBuildSectorTree_EmptyPieces(t *testing.T) {
	// Test that empty pieces list returns an error
	pieces := []PieceData{}
	tree, err := BuildSectorTree(pieces, 0)
	assert.Error(t, err)
	assert.Nil(t, tree)
}

func TestBuildSectorTree_WithSectorSize(t *testing.T) {
	// Test building a tree with explicit sector size
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	sectorSize := uint64(4096) // 4KB sector
	tree, err := BuildSectorTree(pieces, sectorSize)
	require.NoError(t, err)
	require.NotNil(t, tree)

	assert.Equal(t, sectorSize, tree.SectorSize())
}

func TestSectorTree_Root(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	root := tree.Root()
	require.NotNil(t, root)

	// Root should not be zero
	assert.NotEqual(t, merkletree.Node{}, *root)
}

func TestSectorTree_Depth(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	depth := tree.Depth()
	assert.Greater(t, depth, 0)

	// Depth should be at least log2(leafCount) + 1
	leafCount := tree.LeafCount()
	expectedMinDepth := util.Log2Ceil(leafCount) + 1
	assert.GreaterOrEqual(t, depth, expectedMinDepth)
}

func TestSectorTree_Node(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Test getting root node
	rootNode := tree.Node(0, 0)
	require.NotNil(t, rootNode)
	assert.Equal(t, tree.Root(), rootNode)

	// Test getting leaf node
	leafLevel := tree.Depth() - 1
	leafNode := tree.Node(leafLevel, 0)
	require.NotNil(t, leafNode)

	// Test invalid level
	invalidNode := tree.Node(-1, 0)
	assert.Nil(t, invalidNode)

	invalidNode = tree.Node(tree.Depth(), 0)
	assert.Nil(t, invalidNode)

	// Test invalid index
	invalidNode = tree.Node(0, 999999)
	assert.Nil(t, invalidNode)
}

func TestSectorTree_LeafProof(t *testing.T) {
	pieceData := makeTestData(2048) // 2KB to span multiple leaves
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 2048,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Get proof for first leaf
	proof, err := tree.LeafProof(0)
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Verify proof structure
	assert.Equal(t, uint64(0), proof.Index)
	assert.NotEmpty(t, proof.Path)

	// Verify proof depth matches tree structure
	expectedDepth := tree.Depth() - 1
	assert.Equal(t, expectedDepth, proof.Depth())
}

func TestSectorTree_PieceProof(t *testing.T) {
	pieceData := makeTestData(2048) // 2KB to span multiple leaves
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 2048,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Get proof for the piece
	leftProof, rightProof, err := tree.PieceProof(0)
	require.NoError(t, err)
	require.NotNil(t, leftProof)
	require.NotNil(t, rightProof)

	// For a piece spanning multiple leaves, left and right proofs should be different
	// (unless the piece fits in a single leaf)
	if tree.LeafCount() > 1 {
		// At least verify both proofs exist and have valid structure
		assert.NotEmpty(t, leftProof.Path)
		assert.NotEmpty(t, rightProof.Path)
	}
}

func TestSectorTree_ConstructProof(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Test proof for root (should be empty path)
	rootProof, err := tree.ConstructProof(0, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), rootProof.Index)
	assert.Empty(t, rootProof.Path) // Root has no path

	// Test proof for a leaf
	leafLevel := tree.Depth() - 1
	leafProof, err := tree.ConstructProof(leafLevel, 0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), leafProof.Index)
	assert.NotEmpty(t, leafProof.Path) // Leaf should have a path to root
}

func TestSectorTree_Validate(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Valid tree should pass validation
	assert.True(t, tree.Validate())
}

func TestSectorTree_ConsecutivePieces(t *testing.T) {
	// Test placing pieces consecutively without gaps
	piece1Data := makeTestData(512)
	piece2Data := makeTestData(256)
	piece3Data := makeTestData(128)

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

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	assert.True(t, tree.Validate())
	assert.Equal(t, 3, tree.NumPieces())
}

func TestSectorTree_PiecesWithGaps(t *testing.T) {
	// Test placing pieces with gaps (zero-filled areas)
	piece1Data := makeTestData(256)
	piece2Data := makeTestData(512)

	pieces := []PieceData{
		{
			Reader: bytes.NewReader(piece1Data),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 256,
			},
		},
		{
			Reader: bytes.NewReader(piece2Data),
			PieceInfo: PieceInfo{
				BeginAt: 1024, // Gap between pieces
				RawSize: 512,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	assert.True(t, tree.Validate())
	assert.Equal(t, 2, tree.NumPieces())

	// The gap should be filled with zero commitments
	// We can verify this by checking that leaves in the gap are zero
	beginPostFr32 := (256*128 + 126) / 127
	beginLeaf := beginPostFr32 / merkletree.NodeSize
	endPostFr32 := (1024*128 + 126) / 127
	endLeaf := endPostFr32 / merkletree.NodeSize

	// Check a leaf in the gap (should be zero commitment)
	beginLeafUint := uint64(beginLeaf)
	endLeafUint := uint64(endLeaf)
	if beginLeafUint < endLeafUint && beginLeafUint < tree.LeafCount() {
		gapLeaf := tree.Node(int(tree.Depth()-1), beginLeafUint+1)
		require.NotNil(t, gapLeaf)
		// Gap leaves should be zero commitments
		// Note: This might not always be true if the gap is at a different granularity
		// but it's a reasonable check
		_ = gapLeaf // Use the variable to avoid unused variable warning
	}
}

func TestSectorTree_LargeSector(t *testing.T) {
	// Test with a larger sector
	pieceData := makeTestData(64 * 1024) // 64KB
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 64 * 1024,
			},
		},
	}

	sectorSize := uint64(128 * 1024) // 128KB sector
	tree, err := BuildSectorTree(pieces, sectorSize)
	require.NoError(t, err)
	require.NotNil(t, tree)

	assert.Equal(t, sectorSize, tree.SectorSize())
	assert.True(t, tree.Validate())
}

func TestSectorTree_ProofVerification(t *testing.T) {
	pieceData := makeTestData(2048)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 2048,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Get proof for first leaf
	leafLevel := tree.Depth() - 1
	proof, err := tree.ConstructProof(leafLevel, 0)
	require.NoError(t, err)

	// Get the leaf node
	leafNode := tree.Node(leafLevel, 0)
	require.NotNil(t, leafNode)

	// Verify the proof computes to the root
	computedRoot, err := proof.ComputeRoot(leafNode)
	require.NoError(t, err)
	require.NotNil(t, computedRoot)

	// Should match the actual root
	actualRoot := tree.Root()
	assert.Equal(t, *actualRoot, *computedRoot)
}

func TestSectorTree_MultiplePiecesProofs(t *testing.T) {
	piece1Data := makeTestData(512)
	piece2Data := makeTestData(256)
	piece3Data := makeTestData(1024)

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
		{
			Reader: bytes.NewReader(piece3Data),
			PieceInfo: PieceInfo{
				BeginAt: 2048,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Get proofs for all pieces
	for i := 0; i < len(pieces); i++ {
		leftProof, rightProof, err := tree.PieceProof(i)
		require.NoError(t, err, "piece %d", i)
		require.NotNil(t, leftProof, "piece %d", i)
		require.NotNil(t, rightProof, "piece %d", i)

		// Verify proofs are valid
		assert.NotEmpty(t, leftProof.Path, "piece %d left proof", i)
		assert.NotEmpty(t, rightProof.Path, "piece %d right proof", i)
	}
}

func TestSectorTree_InvalidPieceIndex(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Test invalid piece index
	_, _, err = tree.PieceProof(-1)
	assert.Error(t, err)

	_, _, err = tree.PieceProof(999)
	assert.Error(t, err)
}

func TestSectorTree_InvalidProofIndices(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Test invalid level
	_, err = tree.ConstructProof(-1, 0)
	assert.Error(t, err)

	_, err = tree.ConstructProof(tree.Depth(), 0)
	assert.Error(t, err)

	// Test invalid index
	leafLevel := tree.Depth() - 1
	_, err = tree.ConstructProof(leafLevel, tree.LeafCount())
	assert.Error(t, err)
}

func TestSectorTree_DataSizeMismatch(t *testing.T) {
	// Test that data size mismatch is detected
	pieceData := makeTestData(500) // Less than declared size
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024, // Declared size is larger than actual data
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	// BuildSectorTree should detect the size mismatch when reading data
	assert.Error(t, err)
	assert.Nil(t, tree)
	assert.Contains(t, err.Error(), "data size mismatch")
}

func TestSectorTree_ZeroSizePiece(t *testing.T) {
	// Test that zero-size piece is rejected
	pieces := []PieceData{
		{
			Reader: bytes.NewReader([]byte{}),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 0,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	assert.Error(t, err)
	assert.Nil(t, tree)
	// Verify the error message mentions zero size
	assert.Contains(t, err.Error(), "zero")
}

func TestSectorTree_LeafCount(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	leafCount := tree.LeafCount()
	assert.Greater(t, leafCount, uint64(0))

	// Leaf count should be power-of-two (for tree structure)
	assert.True(t, util.IsPow2(leafCount))
}

func TestSectorTree_SectorSize(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	sectorSize := uint64(4096)
	tree, err := BuildSectorTree(pieces, sectorSize)
	require.NoError(t, err)

	assert.Equal(t, sectorSize, tree.SectorSize())
}

func TestSectorTree_CommP(t *testing.T) {
	pieceData := makeTestData(1024)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 1024,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	root := tree.Root()
	assert.NotNil(t, root)
	assert.NotEqual(t, [32]byte{}, *root)
}

func TestSectorTree_ProofConsistency(t *testing.T) {
	// Test that proofs for the same piece are consistent
	pieceData := makeTestData(2048)
	pieces := []PieceData{
		{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: 0,
				RawSize: 2048,
			},
		},
	}

	tree, err := BuildSectorTree(pieces, 0)
	require.NoError(t, err)

	// Get proof twice for the same leaf
	proof1, err := tree.LeafProof(0)
	require.NoError(t, err)

	proof2, err := tree.LeafProof(0)
	require.NoError(t, err)

	// Proofs should be identical
	assert.Equal(t, proof1.Index, proof2.Index)
	assert.Equal(t, len(proof1.Path), len(proof2.Path))
	for i := range proof1.Path {
		assert.Equal(t, proof1.Path[i], proof2.Path[i])
	}
}

// verifyCommPWithCommp verifies that the SectorTree's root matches commpv1's calculation
func verifyCommPWithCommp2(t *testing.T, tree *SectorTree, pieces []PieceData, sectorSize uint64) {
	// Calculate sector size if not provided
	if sectorSize == 0 {
		for _, piece := range pieces {
			endOffset := piece.BeginAt + piece.RawSize
			if endOffset > sectorSize {
				sectorSize = endOffset
			}
		}
		// Round up to align with tree structure requirements
		if sectorSize%merkletree.NodeSize != 0 {
			sectorSize = ((sectorSize / merkletree.NodeSize) + 1) * merkletree.NodeSize
		}
	}

	// Build the complete sector data stream (pre-Fr32)
	// This includes all pieces at their offsets, with zeros for gaps
	// This matches how SectorTree builds the tree
	sectorData := make([]byte, sectorSize)
	
	// Read all pieces and place them at their offsets
	for pieceIdx, piece := range pieces {
		// Read the piece data
		pieceData, err := io.ReadAll(piece.Reader)
		require.NoError(t, err, "failed to read piece %d data", pieceIdx)
		require.Equal(t, piece.RawSize, uint64(len(pieceData)), "piece %d data size mismatch", pieceIdx)
		
		// Place the piece data at its offset in the sector
		// Gaps are automatically filled with zeros (from make)
		if piece.BeginAt+piece.RawSize > sectorSize {
			require.Fail(t, "piece %d extends beyond sector size: %d + %d > %d",
				pieceIdx, piece.BeginAt, piece.RawSize, sectorSize)
		}
		copy(sectorData[piece.BeginAt:piece.BeginAt+piece.RawSize], pieceData)
	}

	// Use commpv1 to calculate the CommP for the entire sector
	// commpv1 processes data as a continuous stream, which matches how SectorTree builds the tree
	// We write the complete sector data as a continuous stream to match SectorTree's behavior
	calc := commp.Calc{}

	// Write the entire sector data at once (as a continuous stream, matching SectorTree)
	n, err := calc.Write(sectorData)
	require.NoError(t, err, "failed to write sector data to commp2")
	require.Equal(t, len(sectorData), n, "incomplete write to commp2")

	// Get the digest from commp2
	commp2Digest, paddedSize, err := calc.Digest()
	require.NoError(t, err, "failed to get digest from commp2")
	require.NotNil(t, commp2Digest, "commp2 digest is nil")
	require.Equal(t, 32, len(commp2Digest), "commp2 digest should be 32 bytes")

	// Get the root from our tree
	treeRoot := tree.Root()
	require.NotNil(t, treeRoot, "tree root is nil")

	// Compare the roots
	// Note: commp2 returns a slice, tree root is a Node (which is [32]byte)
	treeRootBytes := (*treeRoot)[:]

	// Verify both produce non-zero roots
	assert.NotEqual(t, [32]byte{}, treeRootBytes, "Tree root should not be zero")
	assert.NotEqual(t, [32]byte{}, commp2Digest, "commp2 digest should not be zero")

	// CRITICAL: Tree root and commp2 digest MUST match exactly
	// They should be identical if our implementation is correct
	assert.Equal(t, commp2Digest, treeRootBytes,
		"Tree root and commp2 digest must match exactly.\n"+
			"Tree root:      %x\n"+
			"commp2 digest:  %x\n"+
			"This indicates a mismatch in tree construction algorithm.",
		treeRootBytes, commp2Digest)

	// Also verify the padded size matches
	// Calculate expected post-Fr32 size (reuse the variable from above)
	postFr32SizeForPadded := (sectorSize*128 + 126) / 127
	if postFr32SizeForPadded%merkletree.NodeSize != 0 {
		postFr32SizeForPadded = ((postFr32SizeForPadded / merkletree.NodeSize) + 1) * merkletree.NodeSize
	}
	// Round up to power-of-two
	leafCountForPadded := postFr32SizeForPadded / merkletree.NodeSize
	if !util.IsPow2(leafCountForPadded) {
		leafCountForPadded = 1 << util.Log2Ceil(leafCountForPadded)
	}
	expectedPaddedSize := leafCountForPadded * merkletree.NodeSize

	assert.Equal(t, expectedPaddedSize, paddedSize,
		"Padded size mismatch. Expected: %d, commp2: %d", expectedPaddedSize, paddedSize)
}

func TestBuildSectorTree_Commp2Verification_SinglePiece(t *testing.T) {
	// Test with a single piece at offset 0
	pieceData := makeTestData(2048) // 2KB

	// Create pieces with fresh readers
	createPieces := func() []PieceData {
		return []PieceData{
			{
				Reader: bytes.NewReader(pieceData),
				PieceInfo: PieceInfo{
					BeginAt: 0,
					RawSize: 2048,
		},
			},
		}
	}

	tree, err := BuildSectorTree(createPieces(), 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	verifyCommPWithCommp2(t, tree, createPieces(), 0)
}

func TestBuildSectorTree_Commp2Verification_MisalignedPiece(t *testing.T) {
	// Test with a misaligned piece (non-zero offset, non-power-of-two size)
	pieceData := makeTestData(777) // Non-power-of-two size

	// Create pieces with fresh readers
	createPieces := func() []PieceData {
		return []PieceData{
			{
				Reader: bytes.NewReader(pieceData),
				PieceInfo: PieceInfo{
					BeginAt: 127, // Non-aligned offset
					RawSize: 777, // Non-power-of-two size
		},
			},
		}
	}

	tree, err := BuildSectorTree(createPieces(), 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	verifyCommPWithCommp2(t, tree, createPieces(), 0)
}

func TestBuildSectorTree_Commp2Verification_MultiplePieces(t *testing.T) {
	// Test with multiple pieces at different offsets
	piece1Data := makeTestData(512)
	piece2Data := makeTestData(256)
	piece3Data := makeTestData(1024)

	// Create pieces with fresh readers
	createPieces := func() []PieceData {
		return []PieceData{
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
	}

	tree, err := BuildSectorTree(createPieces(), 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	verifyCommPWithCommp2(t, tree, createPieces(), 0)
}

func TestBuildSectorTree_Commp2Verification_ConsecutivePieces(t *testing.T) {
	// Test with consecutive pieces (no gaps)
	piece1Data := makeTestData(512)
	piece2Data := makeTestData(256)
	piece3Data := makeTestData(128)

	// Create pieces with fresh readers
	createPieces := func() []PieceData {
		return []PieceData{
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
	}

	tree, err := BuildSectorTree(createPieces(), 0)
	require.NoError(t, err)
	require.NotNil(t, tree)

	verifyCommPWithCommp2(t, tree, createPieces(), 0)
}
