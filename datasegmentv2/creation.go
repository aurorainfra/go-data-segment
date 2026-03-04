package datasegmentv2

import (
	"bytes"
	"io"

	cid "github.com/ipfs/go-cid"
	xerrors "golang.org/x/xerrors"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	commcid "github.com/filecoin-project/go-fil-commcid"
	abi "github.com/filecoin-project/go-state-types/abi"
)

// AggregateV2 represents a verifiable deal aggregation containing multiple pieces
type AggregateV2 struct {
	DealSize abi.PaddedPieceSize
	Index    *IndexDataV2
	Tree     *SectorTree
}

// NewAggregate creates the structure for verifiable deal aggregation
// based on target deal size and pieces that should be included.
// This version uses SectorTree which supports flexible alignment and preserves
// all intermediate nodes for inclusion proof generation.
//
// Parameters:
//   - dealSize: The target size of the aggregate deal
//   - pieces: List of pieces with their data readers, offsets, and sizes
func NewAggregate(dealSize abi.PaddedPieceSize, pieces []PieceData) (*AggregateV2, error) {
	maxEntries := MaxIndexEntriesInDeal(dealSize)
	if uint(len(pieces)) > maxEntries {
		return nil, xerrors.Errorf("too many pieces for a %d sized deal: %d > %d",
			dealSize, len(pieces), maxEntries)
	}

	// Validate pieces and calculate total size
	var piecesTotalSize uint64
	for i, piece := range pieces {
		if piece.RawSize == 0 {
			return nil, xerrors.Errorf("piece %d: RawSize cannot be zero", i)
		}
		if piece.BeginAt < piecesTotalSize {
			return nil, xerrors.Errorf("piece %d: overlap with previous data", i)
		}
		piecesTotalSize = piece.BeginAt + piece.RawSize
	}

	// Check if pieces and index fit in the deal
	indexSize := uint64(maxEntries) * EntrySize
	if piecesTotalSize+indexSize > uint64(dealSize) {
		return nil, xerrors.Errorf(
			"pieces are too large to fit in the deal: %d (pieces) + %d (index) > %d (dealSize)",
			piecesTotalSize, indexSize, dealSize)
	}

	//
	//// Calculate sector size (pre-Fr32-padding)
	//// The sector size should accommodate all pieces plus the index
	//sectorSizePreFr32 := uint64(dealSize.Unpadded())
	//
	//// Read all piece data and create new readers for reuse
	//// This is necessary because bytes.NewReader can only be read once
	//pieceDataList := make([][]byte, len(pieces))
	//piecesWithNewReaders := make([]PieceData, len(pieces))
	//for i, piece := range pieces {
	//	pieceData, err := io.ReadAll(piece.Reader)
	//	if err != nil {
	//		return nil, xerrors.Errorf("reading piece %d data: %w", i, err)
	//	}
	//	if uint64(len(pieceData)) != piece.RawSize {
	//		return nil, xerrors.Errorf("piece %d data size mismatch: expected %d, got %d",
	//			i, piece.RawSize, len(pieceData))
	//	}
	//	pieceDataList[i] = pieceData
	//	piecesWithNewReaders[i] = PieceData{
	//		Reader: bytes.NewReader(pieceData),
	//		PieceInfo: PieceInfo{
	//			BeginAt: piece.BeginAt,
	//			RawSize: piece.RawSize,
	//		},
	//	}
	//}
	//
	//// Create index entries from pieces
	//// We compute CommP for each piece using commp2 with BeginAt to ensure consistency
	//// This matches how pieces are verified independently
	//indexEntries := make([]*SegmentDesc, len(pieces))
	//for i, piece := range piecesWithNewReaders {
	//	// Use commp2 to calculate the CommP for this piece at its offset
	//	// This ensures the CommP matches what would be calculated independently
	//	calc := &commp2.Calc{}
	//	if err := calc.BeginAt(piece.BeginAt); err != nil {
	//		return nil, xerrors.Errorf("piece %d: failed to set BeginAt: %w", i, err)
	//	}
	//
	//	// Write the piece data
	//	n, err := calc.Write(pieceDataList[i])
	//	if err != nil {
	//		return nil, xerrors.Errorf("piece %d: failed to write data to commp2: %w", i, err)
	//	}
	//	if n != len(pieceDataList[i]) {
	//		return nil, xerrors.Errorf("piece %d: incomplete write to commp2: %d != %d", i, n, len(pieceDataList[i]))
	//	}
	//
	//	// Get the CommP digest from commp2
	//	commp2Digest, _, err := calc.Digest()
	//	if err != nil {
	//		return nil, xerrors.Errorf("piece %d: failed to get digest from commp2: %w", i, err)
	//	}
	//	if len(commp2Digest) != 32 {
	//		return nil, xerrors.Errorf("piece %d: invalid digest length: %d", i, len(commp2Digest))
	//	}
	//
	//	// Convert digest to merkletree.Node
	//	var commDs merkletree.Node
	//	copy(commDs[:], commp2Digest)
	//
	//	// Create SegmentDesc entry
	//	entry := NewDataSegmentIndexEntry(
	//		(*fr32.Fr32)(&commDs),
	//		piece.BeginAt,
	//		piece.RawSize,
	//	).WithUpdatedChecksum()
	//
	//	indexEntries[i] = entry
	//}
	//
	//// Create index from entries
	//index := &IndexDataV2{}
	//if err := index.InitFromPieces(indexEntries); err != nil {
	//	return nil, xerrors.Errorf("failed creating index: %w", err)
	//}
	//
	//// Add index entries to the tree by creating a PieceData for the index
	//// The index starts at DataSegmentIndexStartOffset(dealSize) in unpadded bytes
	//indexStartUnpadded := DataSegmentIndexStartOffset(dealSize)
	//
	//// Marshal index to bytes (same logic as IndexReader)
	//indexBytes, err := index.MarshalBinary()
	//if err != nil {
	//	return nil, xerrors.Errorf("failed marshaling index: %w", err)
	//}
	//
	//// Pad to 128-byte boundaries for Fr32
	//if rem := len(indexBytes) % 128; rem != 0 {
	//	indexBytes = append(indexBytes, make([]byte, 128-rem)...)
	//}
	//
	//// Unpad for reading (to get pre-Fr32 size)
	//unpaddedSize := len(indexBytes) - len(indexBytes)/128
	//bNoPad := make([]byte, unpaddedSize)
	//fr32.Unpad(bNoPad, indexBytes)
	//
	//// Calculate the expected unpadded index size (same as IndexReader)
	//unpaddedIndexSize := int64(MaxIndexEntriesInDeal(dealSize) * EntrySize)
	//unpaddedIndexSize = unpaddedIndexSize - unpaddedIndexSize/128
	//paddingSize := unpaddedIndexSize - int64(len(bNoPad))
	//
	//// Ensure paddingSize is non-negative
	//if paddingSize < 0 {
	//	paddingSize = 0
	//}
	//
	//// Create a reader that includes padding (same as IndexReader)
	//var indexReader io.Reader = bytes.NewReader(bNoPad)
	//if paddingSize > 0 {
	//	indexReader = io.MultiReader(bytes.NewReader(bNoPad), io.LimitReader(zeroReader{}, paddingSize))
	//}
	//
	//// Read all index data including padding
	//indexUnpaddedBytes, err := io.ReadAll(indexReader)
	//if err != nil {
	//	return nil, xerrors.Errorf("failed reading index data: %w", err)
	//}
	//
	//// Create a PieceData for the index
	//indexPiece := PieceData{
	//	Reader: bytes.NewReader(indexUnpaddedBytes),
	//	PieceInfo: PieceInfo{
	//		BeginAt: indexStartUnpadded,
	//		RawSize: uint64(len(indexUnpaddedBytes)),
	//	},
	//}
	//
	//// Recreate readers for all pieces before rebuilding the tree
	//// This ensures that pieces can be read again when rebuilding the tree
	//allPieces := make([]PieceData, len(piecesWithNewReaders))
	//for i, pieceData := range pieceDataList {
	//	allPieces[i] = PieceData{
	//		Reader: bytes.NewReader(pieceData),
	//		PieceInfo: PieceInfo{
	//			BeginAt: piecesWithNewReaders[i].BeginAt,
	//			RawSize: piecesWithNewReaders[i].RawSize,
	//		},
	//	}
	//}
	//allPieces = append(allPieces, indexPiece)
	//treeWithIndex, err := BuildSectorTree(allPieces, sectorSizePreFr32)
	//if err != nil {
	//	return nil, xerrors.Errorf("failed building sector tree with index: %w", err)
	//}
	//
	//agg := AggregateV2{
	//	DealSize: dealSize,
	//	Index:    index,
	//	Tree:     treeWithIndex,
	//}
	//
	//return &agg, nil
	return nil, nil
}

// ProofForIndexEntry gathers information required to produce an InclusionProof based on the index
// of data within the DataSegment Index.
func (a AggregateV2) ProofForIndexEntry(idx int) (*InclusionProof, error) {
	if a.Index == nil {
		return nil, xerrors.Errorf("index is nil")
	}
	if idx < 0 || idx >= a.Index.NumPieces() {
		return nil, xerrors.Errorf("invalid piece index %d (max: %d)", idx, a.Index.NumPieces()-1)
	}
	// Use the CollectInclusionProof function which handles all the proof collection logic
	return CollectInclusionProof(a.Tree, a.DealSize, idx)
}

// ProofForPieceCID searches for a piece within the AggregateV2 based on its PieceCID (CommP)
// and gathers all the information required to produce an inclusion proof.
func (a AggregateV2) ProofForPieceCID(commPc cid.Cid) (*InclusionProof, error) {
	if a.Index == nil {
		return nil, xerrors.Errorf("index is nil")
	}

	// Search returns -1 if not found
	idx := a.Index.Search(commPc)
	if idx < 0 {
		return nil, xerrors.Errorf("piece with CommP %s not found in index", commPc.String())
	}

	return a.ProofForIndexEntry(idx)
}

// PieceCID returns the PieceCID of the deal containing all subdeals and the index
func (a AggregateV2) PieceCID() (cid.Cid, error) {
	root := a.Tree.Root()
	if root == nil {
		return cid.Undef, xerrors.Errorf("tree root is nil")
	}
	return commcid.PieceCommitmentV1ToCID(root[:])
}

// IndexPieceCID returns the PieceCID of the index
func (a AggregateV2) IndexPieceCID() (cid.Cid, error) {
	if a.Index.NumPieces() == 0 {
		return cid.Undef, xerrors.Errorf("index is empty")
	}

	// Calculate the index area start position in padded bytes
	iAS := indexAreaStart(a.DealSize)

	// Calculate the leaf indices for the index area
	// Index starts at iAS (padded bytes), convert to leaf index
	indexStartLeaf := iAS / merkletree.NodeSize

	// Each index entry consists of NodesPerEntry (4) leaf nodes
	// Calculate the end leaf index (exclusive)
	numIndexEntries := uint64(a.Index.NumPieces())
	indexEndLeaf := indexStartLeaf + numIndexEntries*uint64(NodesPerEntry)

	// Find the root of the smallest subtree containing all index entries
	leafLevel := a.Tree.Depth() - 1
	indexRootLevel, indexRootIndex := FindSubtreeRoot(leafLevel, indexStartLeaf, indexEndLeaf)

	// Get the node at the calculated level and index
	node := a.Tree.Node(indexRootLevel, indexRootIndex)
	if node == nil {
		return cid.Undef, xerrors.Errorf("index root node not found at level %d, index %d (indexStartLeaf: %d, indexEndLeaf: %d)",
			indexRootLevel, indexRootIndex, indexStartLeaf, indexEndLeaf)
	}

	return commcid.PieceCommitmentV1ToCID(node[:])
}

// IndexReader returns a reader for the index containing unpadded bytes of the index
func (a AggregateV2) IndexReader() (io.Reader, error) {
	b, err := a.Index.MarshalBinary()
	if err != nil {
		return nil, xerrors.Errorf("marshaling index: %w", err)
	}

	// Pad to 128-byte boundaries for Fr32
	if rem := len(b) % 128; rem != 0 {
		b = append(b, make([]byte, 128-rem)...)
	}

	// Unpad for reading
	unpaddedSize := len(b) - len(b)/128
	bNoPad := make([]byte, unpaddedSize)
	fr32.Unpad(bNoPad, b)

	unpaddedIndexSize := int64(MaxIndexEntriesInDeal(a.DealSize) * EntrySize)
	unpaddedIndexSize = unpaddedIndexSize - unpaddedIndexSize/128
	paddingSize := unpaddedIndexSize - int64(len(bNoPad))

	return io.MultiReader(bytes.NewReader(bNoPad), io.LimitReader(zeroReader{}, paddingSize)), nil
}

// IndexSize returns the size of the index
func (a AggregateV2) IndexSize() (abi.PaddedPieceSize, error) {
	size := abi.PaddedPieceSize(uint64(MaxIndexEntriesInDeal(a.DealSize)) * EntrySize)
	if err := size.Validate(); err != nil {
		return abi.PaddedPieceSize(1<<64 - 1), xerrors.Errorf("validating index size %v, report this: %w", size, err)
	}
	return size, nil
}

// indexAreaStart returns the starting position of the index area in padded bytes
func indexAreaStart(sizePa abi.PaddedPieceSize) uint64 {
	return uint64(sizePa) - uint64(MaxIndexEntriesInDeal(sizePa))*uint64(EntrySize)
}

type zeroReader struct{}

var _ io.Reader = zeroReader{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}
