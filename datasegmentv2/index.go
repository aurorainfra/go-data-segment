package datasegmentv2

import (
	"bytes"
	"encoding"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
	"io"
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
	InitFromPieces(dealInfos []*SegmentDesc) error
	NumPieces() int
	Entry(idx int) *SegmentDesc
	Search(cid cid.Cid) int
	ListPieces() []*SegmentDesc

	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// MaxIndexEntriesInDeal defines the maximum number of index entries in for a given size of a deal
func MaxIndexEntriesInDeal(dealSize abi.PaddedPieceSize) uint {
	res := uint(1) << util.Log2Ceil(uint64(dealSize)/2048/uint64(EntrySize))
	if res < NodesPerEntry {
		return NodesPerEntry
	}
	return res
}

type IndexDataV2 struct {
	Entries []*SegmentDesc
}

var _ PieceIndex = (*IndexDataV2)(nil)

func NewIndexFromPieces(data []io.Reader, offsets []int64, lens []int64) (*IndexDataV2, error) {
	return nil, nil
}

// InitFromPieces initializes the index from piece information
func (id *IndexDataV2) InitFromPieces(pieces []*SegmentDesc) error {
	entries := make([]*SegmentDesc, 0, len(pieces))
	for i := range pieces {
		sd := &SegmentDesc{}
		*sd = *pieces[i]
		entries = append(entries, sd)
	}
	id.Entries = entries
	return nil
}

// NumPieces returns the number of entries in the index
func (id *IndexDataV2) NumPieces() int {
	return len(id.Entries)
}

// Entry returns the segment description at the given index
func (id *IndexDataV2) Entry(idx int) *SegmentDesc {
	if idx < 0 || idx >= len(id.Entries) {
		return nil
	}
	return id.Entries[idx]
}

// Search finds the index of a segment by its PieceCID
// Returns -1 if not found
func (id *IndexDataV2) Search(c cid.Cid) int {
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

func (id *IndexDataV2) ListPieces() []*SegmentDesc {
	entries := []*SegmentDesc{}
	for i := range id.Entries {
		if id.Entries[i] != nil {
			entries = append(entries, id.Entries[i])
		}
	}
	return entries
}

// IndexSize returns the size of the index. Defined to be number of entries * 64 bytes
func (i *IndexDataV2) IndexSize() uint64 {
	return uint64(i.NumPieces()) * uint64(EntrySize)
}

var _ encoding.BinaryMarshaler = IndexDataV2{}
var _ encoding.BinaryUnmarshaler = (*IndexDataV2)(nil)

func (id IndexDataV2) MarshalBinary() (data []byte, err error) {
	res := make([]byte, EntrySize*len(id.Entries))
	for i, r := range id.Entries {
		if r != nil {
			r.SerializeFr32Into(res[i*EntrySize : (i+1)*EntrySize])
		}
	}
	return res, nil
}

func (id *IndexDataV2) UnmarshalBinary(data []byte) error {
	if rem := len(data) % EntrySize; rem != 0 {
		return xerrors.Errorf("data to unmarshal is not a multiple of EntrySize: %d % %d != 0 (%d)",
			len(data), EntrySize, rem)
	}

	*id = IndexDataV2{}
	numEntries := len(data) / EntrySize
	id.Entries = make([]*SegmentDesc, numEntries)
	for i := 0; i < numEntries; i++ {
		var entry SegmentDesc
		err := entry.UnmarshalBinary(data[i*EntrySize : (i+1)*EntrySize])
		if err != nil {
			return xerrors.Errorf("unamrshaling entry at index %d: %w", i, err)
		}
		id.Entries[i] = &entry
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
