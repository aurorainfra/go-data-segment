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

	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// MaxIndexEntriesInDeal defines the maximum number of index entries in for a given size of a deal
func MaxIndexEntriesInDeal(dealSize abi.PaddedPieceSize) uint {
	res := uint(1) << util.Log2Ceil(uint64(dealSize)/2048/uint64(EntrySizeV2))
	if res < 4 {
		return 4
	}
	return res
}

type IndexData struct {
	Entries      []SegmentDescV2
	ValidEntries []bool
}

var _ PieceIndex = (*IndexData)(nil)

// InitFromDeals initializes the index from deal information
func (id *IndexData) InitFromDeals(dealInfos []merkletree.CommAndLoc) error {
	entries := make([]SegmentDescV2, 0, len(dealInfos))
	for _, di := range dealInfos {
		size := 1 << di.Loc.Level * merkletree.NodeSize
		sd := SegmentDescV2{
			CommDs:              di.Comm,
			Offset:              di.Loc.LeafIndex() * merkletree.NodeSize,
			Size:                uint64(size),
			RawSize:             uint64(size), // Default to size for v1 compatibility
			Multicodec:          MulticodecRaw,
			MulticodecDependent: merkletree.Node{},
			ACLType:             0,
			ACLData:             0,
			Reserved:            [7]byte{},
			Checksum:            [ChecksumSize]byte{},
		}
		sd.Checksum = sd.computeChecksum()
		entries = append(entries, sd)
	}
	id.Entries = entries
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
	return &id.Entries[idx]
}

// Search finds the index of a segment by its PieceCID
// Returns -1 if not found
func (id IndexData) Search(c cid.Cid) int {
	comm, err := commcid.CIDToPieceCommitmentV1(c)
	if err != nil {
		return -1
	}
	for i, e := range id.Entries {
		if bytes.Equal(e.CommDs[:], comm[:]) {
			return i
		}
	}
	return -1
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
		r.SerializeFr32Into(res[i*EntrySizeV2 : (i+1)*EntrySizeV2])
	}
	return res, nil
}

func (id *IndexData) UnmarshalBinary(data []byte) error {
	if rem := len(data) % EntrySizeV2; rem != 0 {
		return xerrors.Errorf("data to unmarshal is not a multiple of EntrySizeV2: %d % %d != 0 (%d)",
			len(data), EntrySizeV2, rem)
	}

	*id = IndexData{}
	id.Entries = make([]SegmentDescV2, len(data)/EntrySizeV2)
	for i := 0; i < len(id.Entries); i++ {
		err := id.Entries[i].UnmarshalBinary(data[i*EntrySizeV2 : (i+1)*EntrySizeV2])
		if err != nil {
			return xerrors.Errorf("unamrshaling entry at index %d: %w", i, err)
		}
	}
	return nil
}

func (id IndexData) Validate() error {
	for i, e := range id.Entries {
		if err := e.Validate(); err != nil {
			return xerrors.Errorf("entry at index %d failed validation: %w", i, err)
		}
	}
	return nil
}

func MakeDataSegmentIdx(commDs *fr32.Fr32, offset uint64, size uint64) (SegmentDescV2, error) {
	en := SegmentDescV2{
		CommDs:              *(*merkletree.Node)(commDs),
		Offset:              offset,
		Size:                size,
		RawSize:             size, // Default to size if not specified (v1 compatibility)
		Multicodec:          MulticodecRaw,
		MulticodecDependent: merkletree.Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [7]byte{},
	}
	en.Checksum = en.computeChecksum()
	return en, nil
}

func MakeSegDescs(segments []merkletree.Node, segmentSizes []uint64) ([]merkletree.Node, error) {
	if len(segments) != len(segmentSizes) {
		return nil, xerrors.New("number of segment roots and segment sizes has to match")
	}
	res := make([]merkletree.Node, 4*len(segments))
	curOffset := uint64(0)
	for i, segment := range segments {
		s := fr32.Fr32(segment)
		// TODO: fix segment desciption to be in bytes
		// XXX
		currentDesc, err := MakeDataSegmentIdx(&s, curOffset*merkletree.NodeSize, segmentSizes[i]*merkletree.NodeSize)
		if err != nil {
			return nil, err
		}
		// Use IntoNodes() directly for better performance
		nodes := currentDesc.IntoNodes()
		res[4*i] = nodes[0]
		res[4*i+1] = nodes[1]
		res[4*i+2] = nodes[2]
		res[4*i+3] = nodes[3]
		curOffset += 1 << util.Log2Ceil(segmentSizes[i])
	}
	return res, nil
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

// SerializeIndex encodes a data segment Inclusion into a byte array, after validating that the structure is valid
func SerializeIndex(index *IndexData) ([]byte, error) {
	res := make([]byte, EntrySizeV2*index.NumEntries())
	for i := 0; i < index.NumEntries(); i++ {
		index.Entry(i).SerializeFr32Into(res[i*EntrySizeV2 : (i+1)*EntrySizeV2])
	}
	return res, nil
}
