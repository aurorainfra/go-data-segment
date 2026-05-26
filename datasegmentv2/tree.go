package datasegmentv2

import (
	"hash"
	"io"
	"math/bits"
	"sync"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	sha256simd "github.com/minio/sha256-simd"
	"golang.org/x/xerrors"
)

const (
	commpDigestSize = 32
	maxLayers       = 31
)

var (
	// stackedNulPadding matches commp2's zero commitment calculation
	// This is computed once and cached
	stackedNulPaddingOnce sync.Once
	stackedNulPadding     [maxLayers]merkletree.Node
)

// initStackedNulPadding initializes stackedNulPadding using commp2's algorithm
func initStackedNulPadding() {
	h := sha256simd.New()

	// Level 0 is all zeros
	stackedNulPadding[0] = merkletree.Node{}

	// For level > 0: stackedNulPadding[i] = hash(stackedNulPadding[i-1], stackedNulPadding[i-1]) with top 2 bits cleared
	for i := 1; i < maxLayers; i++ {
		h.Reset()
		h.Write(stackedNulPadding[i-1][:])
		h.Write(stackedNulPadding[i-1][:])
		digest := h.Sum(nil)
		node := merkletree.Node(digest)
		// Clear top 2 bits (same as commp2)
		node[commpDigestSize-1] &= 0x3F
		stackedNulPadding[i] = node
	}
}

// getCommp2ZeroCommitment returns the zero commitment for a given level using commp2's algorithm
func getCommp2ZeroCommitment(level int) merkletree.Node {
	stackedNulPaddingOnce.Do(initStackedNulPadding)

	if level < 0 || level >= maxLayers {
		// Fallback to standard zero commitment if level is out of range
		return merkletree.ZeroCommitmentForLevel(level)
	}

	return stackedNulPadding[level]
}

type PieceInfo struct {
	// BeginAt is the pre-Fr32-padding offset from the start of the sector where this piece begins
	BeginAt uint64

	// RawSize is the pre-Fr32-padding size of the actual piece data
	RawSize uint64
}

// PieceData describes a piece to be placed in the sector tree
type PieceData struct {
	// Reader provides the raw piece data (pre-Fr32-padding)
	Reader io.Reader

	PieceInfo
}

// SectorTree builds a complete Merkle tree for a sector containing multiple pieces,
// similar to commp2 library but with all intermediate nodes cached for inclusion proofs.
//
// The tree is constructed such that:
//   - Nodes within piece boundaries use actual data hashes
//   - Nodes outside piece boundaries use zero commitments
//   - All intermediate nodes are cached for inclusion proof generation
//
// This allows proving that any piece exists in the sector tree.
type SectorTree struct {
	// nodes stores all tree nodes by level, from root (level 0) to leaves (level depth-1)
	// nodes[level][index] gives the node at that level and index
	nodes [][]merkletree.Node

	// depth is the number of levels in the tree (root is level 0)
	depth int

	// sectorSize is the pre-Fr32-padding size of the entire sector
	sectorSize uint64

	// actualLeaves is the number of leaves with actual data (matches commp2's totalLeaves)
	actualLeaves uint64

	// pieces stores information about all pieces in the sector
	pieces []PieceInfo
}

// BuildSectorTree constructs a Merkle tree for a sector containing multiple pieces.
// This is similar to commp2's computation but preserves all nodes for proof generation.
//
// Parameters:
//   - pieces: List of pieces to place in the sector, each with its offset and data
//   - sectorSize: Pre-Fr32-padding size of the entire sector
//
// If sectorSize is 0, it will be calculated automatically based on the pieces.
func BuildSectorTree(pieces []PieceData, sectorSize uint64) (*SectorTree, error) {
	// Validate pieces and calculate minimum sector size if needed
	if len(pieces) == 0 {
		return nil, xerrors.Errorf("at least one piece is required")
	}

	// Validate that all pieces have non-zero size
	for i, piece := range pieces {
		if piece.RawSize == 0 {
			return nil, xerrors.Errorf("piece %d: RawSize cannot be zero", i)
		}
	}

	// If sectorSize is not provided, calculate minimum needed size
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

	// Validate that sectorSize is non-zero after calculation
	if sectorSize == 0 {
		return nil, xerrors.Errorf("calculated sector size is zero, all pieces must have non-zero size")
	}

	// Calculate the number of leaf nodes needed for the sector
	// After Fr32 padding: post-Fr32 = ceil(pre-Fr32 * 128 / 127)
	postFr32Size := (sectorSize*128 + 126) / 127
	if postFr32Size%merkletree.NodeSize != 0 {
		postFr32Size = ((postFr32Size / merkletree.NodeSize) + 1) * merkletree.NodeSize
	}

	// Round up to power-of-two for tree structure
	leafCount := postFr32Size / merkletree.NodeSize
	if leafCount == 0 {
		return nil, xerrors.Errorf("calculated leaf count is zero, sector size is too small")
	}
	if !util.IsPow2(leafCount) {
		leafCount = 1 << util.Log2Ceil(leafCount)
	}

	depth := util.Log2Ceil(leafCount) + 1 // +1 for root level
	if depth <= 0 {
		return nil, xerrors.Errorf("calculated tree depth is invalid: %d", depth)
	}

	pieceInfos := make([]PieceInfo, 0, len(pieces))
	readers := make([]io.Reader, 0, len(pieces))
	for _, p := range pieces {
		pieceInfos = append(pieceInfos, PieceInfo{
			BeginAt: p.BeginAt,
			RawSize: p.RawSize,
		})
		readers = append(readers, p.Reader)
	}

	tree := &SectorTree{
		nodes:        make([][]merkletree.Node, depth),
		depth:        depth,
		sectorSize:   sectorSize,
		actualLeaves: 0, // Will be set in buildLeaves()
		pieces:       pieceInfos,
	}

	// Initialize all levels
	for level := 0; level < depth; level++ {
		tree.nodes[level] = make([]merkletree.Node, 1<<level)
	}

	// Build the tree bottom-up, starting from leaves
	if err := tree.buildLeaves(readers); err != nil {
		return nil, xerrors.Errorf("building leaves: %w", err)
	}

	// Build internal nodes bottom-up
	tree.buildInternalNodes()

	return tree, nil
}

// buildLeaves constructs the leaf level of the tree
// This matches commp2's behavior: build the entire sector as a continuous pre-Fr32 stream,
// then apply Fr32 padding to the whole sector, then build the Merkle tree.
func (t *SectorTree) buildLeaves(readers []io.Reader) error {
	leafLevel := t.depth - 1
	leafCount := len(t.nodes[leafLevel])

	// Step 1: Build the complete pre-Fr32 sector data
	// This includes all pieces at their offsets, with zeros for gaps
	sectorPreFr32 := make([]byte, t.sectorSize)

	// Read all pieces and place them at their offsets
	for pieceIdx, piece := range t.pieces {
		pieceData, err := io.ReadAll(readers[pieceIdx])
		if err != nil {
			return xerrors.Errorf("reading piece %d data: %w", pieceIdx, err)
		}

		if uint64(len(pieceData)) != piece.RawSize {
			return xerrors.Errorf("piece %d data size mismatch: expected %d, got %d",
				pieceIdx, piece.RawSize, len(pieceData))
		}

		// Place the piece data at its offset in the sector
		if piece.BeginAt+piece.RawSize > t.sectorSize {
			return xerrors.Errorf("piece %d extends beyond sector size: %d + %d > %d",
				pieceIdx, piece.BeginAt, piece.RawSize, t.sectorSize)
		}
		copy(sectorPreFr32[piece.BeginAt:piece.BeginAt+piece.RawSize], pieceData)
	}

	// Step 2: Apply Fr32 padding to the entire sector
	// fr32.Pad requires: len(in) % 127 == 0, len(out) % 128 == 0
	// Calculate the required sizes based on actual sector size
	preFr32Chunks := (t.sectorSize + 126) / 127
	preFr32PaddedSize := preFr32Chunks * 127
	if preFr32PaddedSize < t.sectorSize {
		preFr32PaddedSize += 127
		// Recalculate chunks after padding
		preFr32Chunks = preFr32PaddedSize / 127
	}

	// Calculate post-Fr32 size (matches commp2's calculation)
	// postFr32 = preFr32 * 128 / 127 (each 127-byte chunk becomes 128 bytes)
	postFr32PaddedSize := preFr32Chunks * 128

	// Calculate actual number of leaves processed (matches commp2's totalLeaves)
	const numLeavesPerQuad = 4
	lastQuadIdx := preFr32Chunks - 1
	lastLeafIdx := lastQuadIdx*numLeavesPerQuad + (numLeavesPerQuad - 1) // Extend to all 4 leaves
	t.actualLeaves = lastLeafIdx + 1

	// Round up to power-of-two for tree structure (matches commp2's nextPow2)
	expectedPostFr32Size := uint64(leafCount) * merkletree.NodeSize
	if postFr32PaddedSize < expectedPostFr32Size {
		requiredChunks := expectedPostFr32Size / 128
		preFr32PaddedSize = requiredChunks * 127
		postFr32PaddedSize = expectedPostFr32Size
	}

	// Prepare pre-Fr32 data for padding (must be multiple of 127)
	preFr32Padded := make([]byte, preFr32PaddedSize)
	copy(preFr32Padded, sectorPreFr32)

	// Apply Fr32 padding
	postFr32Padded := make([]byte, postFr32PaddedSize)
	fr32.Pad(preFr32Padded, postFr32Padded)

	// Step 3: Store raw leaf data (post-Fr32 padded) for reduce() to hash
	// commp2's reduce() function at level 0 receives raw leaf data (32 bytes) and hashes it
	zeroCommLevel0 := getCommp2ZeroCommitment(0)
	for i := 0; i < leafCount && i*merkletree.NodeSize < len(postFr32Padded); i++ {
		offset := i * merkletree.NodeSize
		if uint64(i) < t.actualLeaves {
			chunk := postFr32Padded[offset : offset+merkletree.NodeSize]
			copy(t.nodes[leafLevel][i][:], chunk)
		} else {
			t.nodes[leafLevel][i] = zeroCommLevel0
		}
	}
	return nil
}

// hashLeavesAndStore computes parent from two raw leaves and optionally stores hashed leaves
func (t *SectorTree) hashLeavesAndStore(h hash.Hash, left, right *merkletree.Node, leafLevel, leftIdx, rightIdx int) merkletree.Node {
	h.Reset()
	h.Write(left[:])
	h.Write(right[:])
	digest := h.Sum(nil)
	parent := merkletree.Node(digest)
	parent[merkletree.NodeSize-1] &= 0x3F

	// Optionally store hashed leaves (for combineAt, not for reduce)
	if leftIdx >= 0 && uint64(leftIdx) < uint64(len(t.nodes[leafLevel])) {
		h.Reset()
		h.Write(left[:])
		digest := h.Sum(nil)
		hashed := merkletree.Node(digest)
		hashed[merkletree.NodeSize-1] &= 0x3F
		t.nodes[leafLevel][leftIdx] = hashed
	}
	if rightIdx >= 0 && uint64(rightIdx) < uint64(len(t.nodes[leafLevel])) {
		h.Reset()
		h.Write(right[:])
		digest := h.Sum(nil)
		hashed := merkletree.Node(digest)
		hashed[merkletree.NodeSize-1] &= 0x3F
		t.nodes[leafLevel][rightIdx] = hashed
	}
	return parent
}

// buildInternalNodes constructs all internal nodes bottom-up
// This matches commp2's stitchTrees algorithm: uses recursive combineAt function
// that handles left/right children based on isLeft() and uses stackedNulPadding
// for zero commitments in the finalization phase
func (t *SectorTree) buildInternalNodes() {
	leafLevel := t.depth - 1
	leafCount := len(t.nodes[leafLevel])

	// Get zero commitment for level 0 (used for padding leaves)
	zeroCommLevel0 := getCommp2ZeroCommitment(0)

	// Phase 1: Simulate commp2's processBuffer using reduce()
	// Calculate root level first (needed for reduce to know when to stop)
	paddedLeaves := uint64(leafCount)               // leafCount is already power-of-two
	commp2RootLevel := bits.Len64(paddedLeaves) - 1 // e.g., 4 leaves → bits.Len64(4)=3 → rootLevel=2

	var chunkPending [maxLayers]merkletree.Node
	var chunkPendingIdx [maxLayers]uint64
	var chunkPendingValid [maxLayers]bool

	// reduce combines a node into the tree at the given level (commp2's indexing: level 0 = leaves)
	// At level 0, data is raw leaf data (32 bytes) - reduce() doesn't hash individual leaves,
	// it just stores them and combines them when pairing
	// At level 1+, data is already a hash (32 bytes)
	// It directly computes parent hashes and recursively reduces, matching commp2's processBuffer
	h := sha256simd.New()
	var reduce func(levelCommp2 int, nodeIdx uint64, data *merkletree.Node)
	reduce = func(levelCommp2 int, nodeIdx uint64, data *merkletree.Node) {
		if nodeIdx%2 == 0 {
			// On the left, store and wait for right sibling (within this chunk)
			// At level 0, store raw leaf data (will be hashed when combining)
			chunkPending[levelCommp2] = *data
			chunkPendingIdx[levelCommp2] = nodeIdx
			chunkPendingValid[levelCommp2] = true
		} else {
			// On the right: if we have a pending left at this level, combine
			if chunkPendingValid[levelCommp2] && chunkPendingIdx[levelCommp2] == nodeIdx-1 {
				var parent merkletree.Node
				if levelCommp2 == 0 {
					// At level 0, hash raw leaf data together (matching commp2's reduce)
					h.Reset()
					h.Write(chunkPending[levelCommp2][:])
					h.Write(data[:])
					digest := h.Sum(nil)
					parent = merkletree.Node(digest)
					parent[merkletree.NodeSize-1] &= 0x3F
					// Store raw leaf data (for reduce, we store raw, not hashed)
					leftIdx := chunkPendingIdx[levelCommp2]
					if leftIdx < uint64(len(t.nodes[leafLevel])) && t.nodes[leafLevel][leftIdx] == (merkletree.Node{}) {
						t.nodes[leafLevel][leftIdx] = chunkPending[levelCommp2]
					}
					if nodeIdx < uint64(len(t.nodes[leafLevel])) && t.nodes[leafLevel][nodeIdx] == (merkletree.Node{}) {
						t.nodes[leafLevel][nodeIdx] = *data
					}
				} else {
					parent = *computeNode(&chunkPending[levelCommp2], data)
				}
				chunkPendingValid[levelCommp2] = false

				parentLevelCommp2 := levelCommp2 + 1
				parentLevelOur := leafLevel - parentLevelCommp2
				parentIdx := nodeIdx / 2
				if parentLevelOur >= 0 && parentLevelOur < t.depth && parentIdx < uint64(len(t.nodes[parentLevelOur])) {
					existing := t.nodes[parentLevelOur][parentIdx]
					if existing == (merkletree.Node{}) || existing != parent {
						t.nodes[parentLevelOur][parentIdx] = parent
					}
				}

				if parentLevelCommp2 == commp2RootLevel {
					chunkPending[parentLevelCommp2] = parent
					chunkPendingIdx[parentLevelCommp2] = parentIdx
					chunkPendingValid[parentLevelCommp2] = true
					return
				}
				reduce(parentLevelCommp2, parentIdx, &parent)
			} else {
				// No pending left sibling - pad with zero (boundary case)
				zeroPad := getCommp2ZeroCommitment(levelCommp2)
				var parent merkletree.Node
				if levelCommp2 == 0 {
					h.Reset()
					h.Write(zeroPad[:])
					h.Write(data[:])
					digest := h.Sum(nil)
					parent = merkletree.Node(digest)
					parent[merkletree.NodeSize-1] &= 0x3F
					// Store hashed leaf
					if nodeIdx < uint64(len(t.nodes[leafLevel])) {
						h.Reset()
						h.Write(data[:])
						digest := h.Sum(nil)
						hashed := merkletree.Node(digest)
						hashed[merkletree.NodeSize-1] &= 0x3F
						t.nodes[leafLevel][nodeIdx] = hashed
					}
				} else {
					parent = *computeNode(&zeroPad, data)
				}

				parentLevelCommp2 := levelCommp2 + 1
				parentLevelOur := leafLevel - parentLevelCommp2
				parentIdx := nodeIdx / 2
				if parentLevelOur >= 0 && parentLevelOur < t.depth && parentIdx < uint64(len(t.nodes[parentLevelOur])) {
					t.nodes[parentLevelOur][parentIdx] = parent
				}

				if parentLevelCommp2 == commp2RootLevel {
					chunkPending[parentLevelCommp2] = parent
					chunkPendingIdx[parentLevelCommp2] = parentIdx
					chunkPendingValid[parentLevelCommp2] = true
					return
				}
				reduce(parentLevelCommp2, parentIdx, &parent)
			}
		}
	}

	// Process all leaves sequentially (matching commp2's processBuffer)
	// First, process actual leaves (raw data)
	for i := 0; i < int(t.actualLeaves); i++ {
		leafIdx := uint64(i)
		leafData := &t.nodes[leafLevel][i]
		reduce(0, leafIdx, leafData)
	}

	// Then, process padding leaves (zero commitments) if any
	// This ensures all intermediate nodes are properly built
	for i := int(t.actualLeaves); i < leafCount; i++ {
		leafIdx := uint64(i)
		// Ensure padding leaves are zero commitments
		t.nodes[leafLevel][i] = zeroCommLevel0
		reduce(0, leafIdx, &zeroCommLevel0)
	}

	// Phase 2: Simulate commp2's stitchTrees using combineAt()
	// commp2RootLevel was already calculated above

	// pending[level] uses commp2's indexing (level 0 = leaves)
	var pending [maxLayers]merkletree.Node
	var pendingIdx [maxLayers]uint64
	var pendingValid [maxLayers]bool

	// Transfer chunk's left nodes to pending (matching commp2's stitchTrees)
	for levelCommp2 := 0; levelCommp2 < int(maxLayers) && levelCommp2 <= commp2RootLevel; levelCommp2++ {
		if chunkPendingValid[levelCommp2] {
			pending[levelCommp2] = chunkPending[levelCommp2]
			pendingIdx[levelCommp2] = chunkPendingIdx[levelCommp2]
			pendingValid[levelCommp2] = true
		}
	}

	// combineAt combines a left node with a right node and propagates up (matching commp2's stitchTrees)
	var combineAt func(levelCommp2 int, leftIdx uint64, left, right *merkletree.Node)
	combineAt = func(levelCommp2 int, leftIdx uint64, left, right *merkletree.Node) {
		var parent merkletree.Node
		if levelCommp2 == 0 {
			parent = t.hashLeavesAndStore(h, left, right, leafLevel, int(leftIdx), int(leftIdx)+1)
		} else {
			parent = *computeNode(left, right)
		}

		parentIdx := leftIdx / 2
		parentLevelCommp2 := levelCommp2 + 1
		parentLevelOur := leafLevel - parentLevelCommp2
		if parentLevelOur >= 0 && parentLevelOur < t.depth && parentIdx < uint64(len(t.nodes[parentLevelOur])) {
			existing := t.nodes[parentLevelOur][parentIdx]
			if existing == (merkletree.Node{}) || existing != parent {
				t.nodes[parentLevelOur][parentIdx] = parent
			}
		}

		if parentLevelCommp2 == commp2RootLevel {
			pending[parentLevelCommp2] = parent
			pendingIdx[parentLevelCommp2] = parentIdx
			pendingValid[parentLevelCommp2] = true
			return
		}

		if parentIdx%2 == 0 {
			// Parent is a left child
			pending[parentLevelCommp2] = parent
			pendingIdx[parentLevelCommp2] = parentIdx
			pendingValid[parentLevelCommp2] = true
		} else {
			// Parent is a right child
			if pendingValid[parentLevelCommp2] && pendingIdx[parentLevelCommp2] == parentIdx-1 {
				combineAt(parentLevelCommp2, pendingIdx[parentLevelCommp2], &pending[parentLevelCommp2], &parent)
				pendingValid[parentLevelCommp2] = false
			} else {
				zeroPad := getCommp2ZeroCommitment(parentLevelCommp2)
				combineAt(parentLevelCommp2, parentIdx-1, &zeroPad, &parent)
			}
		}
	}

	// Finalize: pad any remaining pending nodes with zero and propagate to root
	// This matches commp2's finalization phase exactly
	for levelCommp2 := 0; levelCommp2 < commp2RootLevel; levelCommp2++ {
		if pendingValid[levelCommp2] {
			zeroPad := getCommp2ZeroCommitment(levelCommp2)
			combineAt(levelCommp2, pendingIdx[levelCommp2], &pending[levelCommp2], &zeroPad)
			pendingValid[levelCommp2] = false
		}
	}

	// Store the root (convert commp2 level to our level: root is at level 0)
	if pendingValid[commp2RootLevel] {
		rootLevelOur := leafLevel - commp2RootLevel
		if rootLevelOur >= 0 && rootLevelOur < t.depth {
			rootIdx := pendingIdx[commp2RootLevel]
			if rootIdx < uint64(len(t.nodes[rootLevelOur])) {
				t.nodes[rootLevelOur][rootIdx] = pending[commp2RootLevel]
			}
		}
	}

	// Post-process: ensure all padding leaves are stored as raw data (all zeros)
	// commp2's reduce() at level 0 uses raw leaf data directly
	zeroRaw := merkletree.Node{}
	for i := int(t.actualLeaves); i < len(t.nodes[leafLevel]); i++ {
		t.nodes[leafLevel][i] = zeroRaw
	}
}

// computeNode computes a Merkle tree node from two child nodes
// This matches commp2's algorithm: uses sha256simd and clears top 2 bits
func computeNode(left, right *merkletree.Node) *merkletree.Node {
	h := sha256simd.New()
	h.Write(left[:])
	h.Write(right[:])
	digest := h.Sum(nil)
	node := merkletree.Node(digest)
	// Truncate the last 2 bits (same as commp2: parentHash[31] &= 0x3F)
	node[merkletree.NodeSize-1] &= 0x3F
	return &node
}

// Root returns the root node of the tree (the CommP for the entire sector)
func (t *SectorTree) Root() *merkletree.Node {
	if len(t.nodes) == 0 || len(t.nodes[0]) == 0 {
		return nil
	}
	return &t.nodes[0][0]
}

// Depth returns the depth of the tree
func (t *SectorTree) Depth() int {
	return t.depth
}

// Node returns the node at the given level and index
func (t *SectorTree) Node(level int, index uint64) *merkletree.Node {
	if level < 0 || level >= t.depth {
		return nil
	}
	if index >= uint64(len(t.nodes[level])) {
		return nil
	}
	return &t.nodes[level][index]
}

// ConstructProof constructs a Merkle proof for the node at the given level and index
// Returns the proof path from the node to the root
func (t *SectorTree) ConstructProof(level int, index uint64) (*merkletree.ProofData, error) {
	if level < 0 || level >= t.depth {
		return nil, xerrors.Errorf("invalid level %d (depth: %d)", level, t.depth)
	}
	if index >= uint64(len(t.nodes[level])) {
		return nil, xerrors.Errorf("invalid index %d for level %d (max: %d)", index, level, len(t.nodes[level]))
	}

	// Build proof path from the node to the root
	proofPath := make([]merkletree.Node, level)
	currentLevel := level
	currentIdx := index

	// Traverse up the tree, collecting sibling nodes
	for currentLevel > 0 {
		parentLevel := currentLevel - 1
		parentIdx := currentIdx / 2

		// Get sibling index
		siblingIdx := currentIdx
		if currentIdx%2 == 0 {
			siblingIdx = currentIdx + 1
		} else {
			siblingIdx = currentIdx - 1
		}

		// Add sibling to proof path if it exists
		if siblingIdx < uint64(len(t.nodes[currentLevel])) {
			proofPath[currentLevel-1] = t.nodes[currentLevel][siblingIdx]
		} else {
			// Sibling doesn't exist, use zero commitment
			proofPath[currentLevel-1] = merkletree.ZeroCommitmentForLevel(currentLevel)
		}

		currentLevel = parentLevel
		currentIdx = parentIdx
	}

	// Reverse the path so it goes from leaf to root
	for i, j := 0, len(proofPath)-1; i < j; i, j = i+1, j-1 {
		proofPath[i], proofPath[j] = proofPath[j], proofPath[i]
	}

	return &merkletree.ProofData{
		Path:  proofPath,
		Index: index,
	}, nil
}

// LeafProof constructs a proof for a specific leaf node
func (t *SectorTree) LeafProof(leafIndex uint64) (*merkletree.ProofData, error) {
	leafLevel := t.depth - 1
	return t.ConstructProof(leafLevel, leafIndex)
}

// PieceProof constructs inclusion proofs for a piece's leftmost and rightmost leaves
// This is needed for misaligned pieces according to FRC-1216
func (t *SectorTree) PieceProof(pieceIndex int) (leftProof, rightProof *merkletree.ProofData, err error) {
	if pieceIndex < 0 || pieceIndex >= len(t.pieces) {
		return nil, nil, xerrors.Errorf("invalid piece index %d (max: %d)", pieceIndex, len(t.pieces)-1)
	}

	piece := t.pieces[pieceIndex]

	// Calculate piece boundaries in terms of post-Fr32 leaf indices
	beginPostFr32 := (piece.BeginAt*128 + 126) / 127
	beginLeaf := beginPostFr32 / merkletree.NodeSize

	endPostFr32 := ((piece.BeginAt+piece.RawSize)*128 + 126) / 127
	endLeaf := (endPostFr32 + merkletree.NodeSize - 1) / merkletree.NodeSize

	// Get proof for leftmost leaf
	leftProof, err = t.LeafProof(beginLeaf)
	if err != nil {
		return nil, nil, xerrors.Errorf("constructing left proof: %w", err)
	}

	// Get proof for rightmost leaf (if different from leftmost)
	if endLeaf > beginLeaf {
		rightProof, err = t.LeafProof(endLeaf - 1)
		if err != nil {
			return nil, nil, xerrors.Errorf("constructing right proof: %w", err)
		}
	} else {
		// Piece fits in a single leaf, right proof is same as left
		rightProof = leftProof
	}

	return leftProof, rightProof, nil
}

// Validate verifies that the tree is correctly constructed
func (t *SectorTree) Validate() bool {
	// Validate that all internal nodes are correctly computed from their children
	for level := 0; level < t.depth-1; level++ {
		childLevel := level + 1
		childCount := len(t.nodes[childLevel])
		parentCount := childCount / 2

		for i := 0; i < parentCount; i++ {
			leftChild := &t.nodes[childLevel][2*i]
			rightChild := &t.nodes[childLevel][2*i+1]

			var expectedParent *merkletree.Node
			// At level 0 (leaf level), leaves are raw data (not hashed)
			// commp2's reduce() uses raw leaf data directly to compute parent
			// So we need to hash raw leaves together directly, not hash them individually first
			if childLevel == t.depth-1 {
				// Leaf level: compute parent from raw leaf data directly (matching commp2's reduce)
				h := sha256simd.New()
				h.Write(leftChild[:])
				h.Write(rightChild[:])
				digest := h.Sum(nil)
				parentHash := merkletree.Node(digest)
				parentHash[merkletree.NodeSize-1] &= 0x3F
				expectedParent = &parentHash
			} else {
				// Level 1+: children are already hashed, use computeNode
				expectedParent = computeNode(leftChild, rightChild)
			}

			actualParent := &t.nodes[level][i]

			if *expectedParent != *actualParent {
				return false
			}
		}
	}
	return true
}

// LeafCount returns the number of leaf nodes in the tree
func (t *SectorTree) LeafCount() uint64 {
	if t.depth == 0 {
		return 0
	}
	return uint64(len(t.nodes[t.depth-1]))
}

// SectorSize returns the pre-Fr32-padding size of the sector
func (t *SectorTree) SectorSize() uint64 {
	return t.sectorSize
}

// NumPieces returns the number of pieces in the sector
func (t *SectorTree) NumPieces() int {
	return len(t.pieces)
}
