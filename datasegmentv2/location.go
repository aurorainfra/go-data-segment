package datasegmentv2

import (
	"golang.org/x/xerrors"
)

const (
	// Constants from commp2 package
	quadPayload     = 127   // bytes per quad (pre-Fr32)
	numLeaves       = 4     // number of FR32 leaves per quad
	leafExpandedSize = 32   // FR32 leaf expanded size (bytes per leaf)
)

// PieceLeafRange represents the leaf node indices for a piece in the tree
type PieceLeafRange struct {
	BeginLeaf uint64 // Starting leaf index (inclusive)
	EndLeaf   uint64 // Ending leaf index (exclusive)
}

// ComputePieceLeafRange calculates the leaf node range for a piece in the tree
// using commp2's BeginAt and Write mechanism.
//
// This function simulates how commp2 processes a piece at a given offset:
// 1. Sets the offset using BeginAt
// 2. Writes the piece data
// 3. Calculates which leaf nodes are affected by the piece
//
// Parameters:
//   - piece: The piece data with its offset and size
//
// Returns:
//   - PieceLeafRange with BeginLeaf (inclusive) and EndLeaf (exclusive) indices
//   - Error if computation fails
func ComputePieceLeafRange(piece PieceData) (*PieceLeafRange, error) {
	if piece.RawSize == 0 {
		return nil, xerrors.Errorf("piece RawSize cannot be zero")
	}

	// Calculate leaf range based on FR32 encoding algorithm
	// The calculation matches commp2's processBuffer logic:
	// - startQuad = BeginAt / 127
	// - posInFirstQuad = BeginAt % 127
	// - firstDataLeaf = startQuad * 4 + payloadPosToLeaf(posInFirstQuad)
	
	start := piece.BeginAt
	end := piece.BeginAt + piece.RawSize
	
	startQuad := start / uint64(quadPayload)
	posInFirstQuad := int(start % uint64(quadPayload))
	
	// Calculate first leaf index (matches commp2's logic in processBuffer)
	// Note: commp2 uses payloadPosToLeaf for firstDataLeaf, not payloadPosToLeafStart
	firstDataLeaf := startQuad*numLeaves + uint64(payloadPosToLeaf(posInFirstQuad))
	
	// Calculate last leaf index
	// For the end position, we need to find the last leaf that contains data
	endQuad := (end + uint64(quadPayload) - 1) / uint64(quadPayload)
	if end > 0 {
		end--
	}
	posInLastQuad := int(end % uint64(quadPayload))
	
	// Use payloadPosToLeaf to find the last leaf containing data
	lastDataLeafInQuad := payloadPosToLeaf(posInLastQuad)
	lastQuadStartLeaf := (endQuad - 1) * numLeaves
	lastDataLeaf := lastQuadStartLeaf + uint64(lastDataLeafInQuad) + 1 // +1 because EndLeaf is exclusive
	
	// Ensure we have at least one leaf
	if lastDataLeaf <= firstDataLeaf {
		lastDataLeaf = firstDataLeaf + 1
	}

	return &PieceLeafRange{
		BeginLeaf: firstDataLeaf,
		EndLeaf:   lastDataLeaf,
	}, nil
}

// FindSubtreeRoot finds the root of the smallest subtree that contains all leaves
// from beginLeaf to endLeaf-1. This is the common ancestor of beginLeaf and (endLeaf-1).
//
// Returns:
//   - level: The level of the subtree root (0 = root, higher = deeper)
//   - index: The index of the subtree root at that level
func FindSubtreeRoot(leafLevel int, beginLeaf, endLeaf uint64) (level int, index uint64) {
	if endLeaf <= beginLeaf {
		// Invalid range, return leaf level
		return leafLevel, beginLeaf
	}

	// Find the common ancestor of beginLeaf and (endLeaf-1)
	leftIdx := beginLeaf
	rightIdx := endLeaf - 1

	// Traverse up the tree until we find a common ancestor
	level = leafLevel
	for leftIdx != rightIdx && level > 0 {
		leftIdx = leftIdx / 2
		rightIdx = rightIdx / 2
		level--
	}

	return level, leftIdx
}

// payloadPosToLeafStart returns the FIRST leaf affected by data starting at this position.
// Due to FR32 bit-shifting, each leaf depends on a range of input bytes:
//   - Leaf 0: input bytes 0-31
//   - Leaf 1: input bytes 31-63 (byte 31 carries into leaf 1, byte 63 shifts into it)
//   - Leaf 2: input bytes 63-95
//   - Leaf 3: input bytes 95-126
// Therefore, boundaries are: [0,32), [32,64), [64,96), [96,127)
//
// This matches commp2's payloadPosToLeafStart function.
func payloadPosToLeafStart(pos int) int {
	switch {
	case pos < 32:
		return 0
	case pos < 64:
		return 1
	case pos < 96:
		return 2
	default:
		return 3
	}
}

// payloadPosToLeaf returns which leaf (0-3) a payload byte position falls into.
// Used for determining the LAST leaf containing data (end position).
// Leaf boundaries: [0,31), [31,62), [62,93), [93,127)
//
// This matches commp2's payloadPosToLeaf function.
func payloadPosToLeaf(pos int) int {
	switch {
	case pos < 31:
		return 0
	case pos < 62:
		return 1
	case pos < 93:
		return 2
	default:
		return 3
	}
}
