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
	if err := dealSize.Validate(); err != nil {
		return nil, xerrors.Errorf("invalid dealSize: %w", err)
	}
	if len(pieces) == 0 {
		return nil, xerrors.Errorf("at least one piece is required")
	}

	maxEntries := MaxIndexEntriesInDeal(dealSize)
	maxDataEntries := maxEntries - 1 // the final entry is the index descriptor
	if uint(len(pieces)) > maxDataEntries {
		return nil, xerrors.Errorf("too many pieces for a %d sized deal: %d > %d",
			dealSize, len(pieces), maxDataEntries)
	}

	indexStartUnpadded := indexAreaStartUnpadded(dealSize)
	pieceDataList := make([][]byte, len(pieces))
	indexEntries := make([]*SegmentDesc, len(pieces))

	// Validate pieces, retain their bytes for tree construction, and build CID entries.
	var piecesTotalSize uint64
	for i, piece := range pieces {
		if piece.Reader == nil {
			return nil, xerrors.Errorf("piece %d: Reader cannot be nil", i)
		}
		if piece.RawSize == 0 {
			return nil, xerrors.Errorf("piece %d: RawSize cannot be zero", i)
		}
		pieceEnd := piece.BeginAt + piece.RawSize
		if pieceEnd < piece.BeginAt {
			return nil, xerrors.Errorf("piece %d: offset plus size overflows", i)
		}
		if piece.BeginAt < piecesTotalSize {
			return nil, xerrors.Errorf("piece %d: overlap with previous data", i)
		}
		piecesTotalSize = pieceEnd

		pieceData, err := io.ReadAll(piece.Reader)
		if err != nil {
			return nil, xerrors.Errorf("reading piece %d data: %w", i, err)
		}
		if uint64(len(pieceData)) != piece.RawSize {
			return nil, xerrors.Errorf("piece %d data size mismatch: expected %d, got %d",
				i, piece.RawSize, len(pieceData))
		}
		pieceDataList[i] = pieceData

		digest, err := blake3Digest(pieceData)
		if err != nil {
			return nil, xerrors.Errorf("piece %d: computing blake3 digest: %w", i, err)
		}
		indexEntries[i] = NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, digest[:], piece.BeginAt, piece.RawSize).
			WithCodec(MulticodecRaw).
			WithUpdatedChecksum()
	}

	if piecesTotalSize > indexStartUnpadded {
		return nil, xerrors.Errorf(
			"pieces are too large to fit in the deal: pieces end at %d, index starts at %d",
			piecesTotalSize, indexStartUnpadded)
	}

	index := &IndexDataV2{
		Entries: indexEntries,
		Offset:  int64(indexStartUnpadded),
	}
	agg := &AggregateV2{
		DealSize: dealSize,
		Index:    index,
	}

	indexReader, err := agg.IndexReader()
	if err != nil {
		return nil, xerrors.Errorf("creating index reader: %w", err)
	}
	indexUnpaddedBytes, err := io.ReadAll(indexReader)
	if err != nil {
		return nil, xerrors.Errorf("reading index data: %w", err)
	}

	allPieces := make([]PieceData, 0, len(pieces)+1)
	for i, pieceData := range pieceDataList {
		allPieces = append(allPieces, PieceData{
			Reader: bytes.NewReader(pieceData),
			PieceInfo: PieceInfo{
				BeginAt: pieces[i].BeginAt,
				RawSize: pieces[i].RawSize,
			},
		})
	}
	allPieces = append(allPieces, PieceData{
		Reader: bytes.NewReader(indexUnpaddedBytes),
		PieceInfo: PieceInfo{
			BeginAt: indexStartUnpadded,
			RawSize: uint64(len(indexUnpaddedBytes)),
		},
	})

	treeWithIndex, err := BuildSectorTree(allPieces, uint64(dealSize.Unpadded()))
	if err != nil {
		return nil, xerrors.Errorf("failed building sector tree with index: %w", err)
	}
	agg.Tree = treeWithIndex

	return agg, nil
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

// ProofForPieceCID searches for a piece within the AggregateV2 based on its indexed content CID
// and gathers all the information required to produce an inclusion proof.
func (a AggregateV2) ProofForPieceCID(pieceCid cid.Cid) (*InclusionProof, error) {
	if a.Index == nil {
		return nil, xerrors.Errorf("index is nil")
	}

	// Search returns -1 if not found
	idx := a.Index.Search(pieceCid)
	if idx < 0 {
		return nil, xerrors.Errorf("piece with CID %s not found in index", pieceCid.String())
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

	// Each index entry consists of NodesPerEntry (4) leaf nodes. The index piece
	// covers the full reserved index area, including zero padding and descriptor.
	numIndexEntries := uint64(MaxIndexEntriesInDeal(a.DealSize))
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
	b, err := a.Index.marshalBinaryWithEntryCount(int(MaxIndexEntriesInDeal(a.DealSize)))
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

	return bytes.NewReader(bNoPad), nil
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

// indexAreaStartUnpadded returns the index start position in pre-Fr32-padding bytes.
func indexAreaStartUnpadded(sizePa abi.PaddedPieceSize) uint64 {
	indexSize := uint64(MaxIndexEntriesInDeal(sizePa)) * uint64(EntrySize)
	return uint64(sizePa.Unpadded()) - (indexSize - indexSize/128)
}
