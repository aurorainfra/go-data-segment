package index

import (
	"bytes"
	"encoding"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

type validationError string

var ErrValidation = validationError("unknown")

func (ve validationError) Error() string {
	return string(ve)
}

func (ve validationError) Is(err error) bool {
	_, ok := err.(validationError)
	return ok
}

type PieceIndex interface {
	InitFromDeals(dealInfos []merkletree.CommAndLoc) error
	NumEntries() int
	Entry(idx int) *SegmentDescV2
	Search(cid cid.Cid) int
	ListEntries() []*SegmentDescV2

	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// MaxIndexEntriesInDeal defines the maximum number of index entries in for a given size of a deal
func MaxIndexEntriesInDeal(dealSize abi.PaddedPieceSize) uint {
	res := uint(1) << util.Log2Ceil(uint64(dealSize)/2048/uint64(EntrySizeV2))
	if res < NodesPerEntry {
		return NodesPerEntry
	}
	return res
}

type IndexData struct {
	Entries  []*SegmentDescV2
	validPos []bool
}

var _ PieceIndex = (*IndexData)(nil)

// InitFromDeals initializes the index from deal information
func (id *IndexData) InitFromDeals(dealInfos []merkletree.CommAndLoc) error {
	entries := make([]*SegmentDescV2, 0, len(dealInfos))
	validPos := make([]bool, len(dealInfos))
	for i, di := range dealInfos {
		size := 1 << di.Loc.Level * merkletree.NodeSize
		sd := NewDataSegmentIndexEntry((*fr32.Fr32)(&di.Comm), di.Loc.LeafIndex()*merkletree.NodeSize, uint64(size))
		entries = append(entries, sd)
		validPos[i] = true
	}
	id.Entries = entries
	id.validPos = validPos
	return nil
}

// NumEntries returns the number of entries in the index
func (id IndexData) NumEntries() int {
	return len(id.Entries)
}

// Entry returns the segment description at the given index
func (id IndexData) Entry(idx int) *SegmentDescV2 {
	if idx < 0 || idx >= len(id.Entries) {
		return nil
	}
	return id.Entries[idx]
}

// Search finds the index of a segment by its PieceCID
// Returns -1 if not found
func (id IndexData) Search(c cid.Cid) int {
	comm, err := commcid.CIDToPieceCommitmentV1(c)
	if err != nil {
		return -1
	}
	for i, e := range id.Entries {
		if e != nil && bytes.Equal(e.CommDs[:], comm[:]) {
			return i
		}
	}
	return -1
}

func (id IndexData) ListEntries() []*SegmentDescV2 {
	entries := []*SegmentDescV2{}
	for i := range id.Entries {
		if id.Entries[i] != nil && id.validPos[i] {
			entries = append(entries, id.Entries[i])
		}
	}
	return entries
}

// IndexSize returns the size of the index. Defined to be number of entries * 64 bytes
func (i IndexData) IndexSize() uint64 {
	return uint64(i.NumEntries()) * uint64(EntrySizeV2)
}

var _ encoding.BinaryMarshaler = IndexData{}
var _ encoding.BinaryUnmarshaler = (*IndexData)(nil)

func (id IndexData) MarshalBinary() (data []byte, err error) {
	res := make([]byte, EntrySizeV2*len(id.Entries))
	for i, r := range id.Entries {
		if r != nil {
			r.SerializeFr32Into(res[i*EntrySizeV2 : (i+1)*EntrySizeV2])
		}
	}
	return res, nil
}

func (id *IndexData) UnmarshalBinary(data []byte) error {
	if rem := len(data) % EntrySizeV2; rem != 0 {
		return xerrors.Errorf("data to unmarshal is not a multiple of EntrySizeV2: %d % %d != 0 (%d)",
			len(data), EntrySizeV2, rem)
	}

	*id = IndexData{}
	numEntries := len(data) / EntrySizeV2
	id.Entries = make([]*SegmentDescV2, numEntries)
	id.validPos = make([]bool, numEntries)
	for i := 0; i < numEntries; i++ {
		var entry SegmentDescV2
		err := entry.UnmarshalBinary(data[i*EntrySizeV2 : (i+1)*EntrySizeV2])
		if err != nil {
			return xerrors.Errorf("unamrshaling entry at index %d: %w", i, err)
		}
		id.Entries[i] = &entry
		id.validPos[i] = true
	}
	return nil
}

// SegmentRoot computes the root of the client's segment's subtree
// treeDepth is the depth of the tree where the client segment is located
// segmentSize is the amount of leafs needed for the client's segment
// segmentOffset is the index of the first leaf where the client's segment starts. 0-indexed
func SegmentRoot(treeDepth int, segmentSize uint64, segmentOffset uint64) (int, uint64) {
	lvl := treeDepth - util.Log2Ceil(uint64(segmentSize)) - 1
	idx := segmentOffset >> util.Log2Ceil(uint64(segmentSize))
	return lvl, idx
}
