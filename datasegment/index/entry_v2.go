package index

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

// EntrySizeV2 is the size of a Data Segment Index Entry v2
// v2 entries consist of 4 Merkle nodes (4 * 32 = 128 bytes)
// This is the serialized size in memory (padded format, aligned to 128-byte boundaries).
const EntrySizeV2 = 4 * merkletree.NodeSize // 128 bytes (4 nodes of 32 bytes each)

// Multicodec values
const (
	MulticodecRaw = 0x55   // Raw binary data
	MulticodecCAR = 0x0202 // CAR format (IPLD)
)

// SegmentDescV2 contains a data segment description (v2 format)
// to be contained as four Fr32 elements in 4 leaf nodes of the data segment index
type SegmentDescV2 struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs merkletree.Node
	// Offset is the offset from the start of the deal in pre-Fr32-padding bytes
	Offset uint64
	// Size is the number of pre-Fr32-padding bytes that is contained in the sub-deal (including padding)
	Size uint64
	// RawSize is the actual size of the meaningful data before any trailing padding (pre-Fr32-padding)
	RawSize uint64
	// Multicodec identifies the content encoding format (0x55 = Raw, 0x0202 = CAR)
	Multicodec uint64
	// MulticodecDependent is extension space for multicodec-specific metadata
	// For Raw and CAR codecs, this MUST be zero
	MulticodecDependent merkletree.Node
	// ACLType is the ACL type indicator (0 = no ACL, other values specified in future FRC)
	ACLType uint8
	// ACLData is ACL type-specific data (MUST be zero when ACLType is 0)
	ACLData uint64
	// Reserved is reserved for future versions of this FRC (MUST be zero in this version)
	Reserved [7]byte // 56 bits = 7 bytes
	// Checksum is a 126 bit checksum (SHA256) computed on all fields above with checksum bits set to zero
	Checksum [ChecksumSize]byte
}

// PieceCID returns the PieceCID of the sub-deal
func (sd SegmentDescV2) PieceCID() cid.Cid {
	c, err := commcid.PieceCommitmentV1ToCID(sd.CommDs[:])
	if err != nil {
		panic("CommDs is always 32 bytes: " + err.Error())
	}
	return c
}

// UnpaddedOffest returns unpadded offset of the sub-deal relative to the deal start
func (sd SegmentDescV2) UnpaddedOffest() uint64 {
	return sd.Offset - sd.Offset/128
}

// UnpaddedLength returns unpadded length of the sub-deal
func (sd SegmentDescV2) UnpaddedLength() uint64 {
	return sd.Size - sd.Size/128
}

func (sd SegmentDescV2) CommAndLoc() merkletree.CommAndLoc {
	lvl := util.Log2Ceil(sd.Size / merkletree.NodeSize)
	res := merkletree.CommAndLoc{
		Comm: sd.CommDs,
		Loc: merkletree.Location{
			Level: lvl,
			Index: sd.Offset / merkletree.NodeSize >> lvl,
		},
	}
	return res
}

func (sd SegmentDescV2) computeChecksum() [ChecksumSize]byte {
	sdCopy := sd
	sdCopy.Checksum = [ChecksumSize]byte{}

	toHash := sdCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:ChecksumSize]
	// Truncate to  126 bits
	res[ChecksumSize-1] &= 0b00111111
	return *(*[ChecksumSize]byte)(res)
}

func (sd SegmentDescV2) withUpdatedChecksum() SegmentDescV2 {
	sd.Checksum = sd.computeChecksum()
	return sd
}

var _ encoding.BinaryMarshaler = SegmentDescV2{}
var _ encoding.BinaryUnmarshaler = (*SegmentDescV2)(nil)

func (sd SegmentDescV2) MarshalBinary() ([]byte, error) {
	return sd.SerializeFr32(), nil
}

func (sd *SegmentDescV2) UnmarshalBinary(data []byte) error {
	if len(data) != EntrySizeV2 {
		return xerrors.Errorf("invalid segment description size: expected %d, got %d", EntrySizeV2, len(data))
	}
	le := binary.LittleEndian

	*sd = SegmentDescV2{}
	// Node 1: CommDS (32 bytes)
	sd.CommDs = *(*merkletree.Node)(data[:merkletree.NodeSize])

	// Node 2: Offset (8 bytes) + NumEntries (8 bytes) + RawSize (8 bytes, but only 62 bits used) + Multicodec (8 bytes)
	offset := merkletree.NodeSize
	sd.Offset = le.Uint64(data[offset:])
	offset += 8
	sd.Size = le.Uint64(data[offset:])
	offset += 8
	sd.RawSize = le.Uint64(data[offset:]) & 0x3FFFFFFFFFFFFFFF // Mask to 62 bits
	offset += 8
	sd.Multicodec = le.Uint64(data[offset:])
	offset += 8

	// Node 3: MulticodecDependent (32 bytes)
	sd.MulticodecDependent = *(*merkletree.Node)(data[offset:])
	offset += merkletree.NodeSize

	// Node 4: ACLType (1 byte) + ACLData (8 bytes) + Reserved (7 bytes) + Checksum (16 bytes)
	sd.ACLType = data[offset]
	offset += 1
	sd.ACLData = le.Uint64(data[offset:])
	offset += 8
	copy(sd.Reserved[:], data[offset:offset+7])
	offset += 7
	copy(sd.Checksum[:], data[offset:offset+ChecksumSize])

	// Don't validate here - let the caller decide whether to validate
	// This allows unmarshaling invalid entries for testing purposes
	return nil
}

func (sd SegmentDescV2) SerializeFr32() []byte {
	res := make([]byte, EntrySizeV2)
	sd.SerializeFr32Into(res)
	return res
}

// SerializeFr32Into serializes the Segment Desctipion into given slice
// Panics if len(slice) < EntrySizeV2
func (sd SegmentDescV2) SerializeFr32Into(slice []byte) {
	_ = slice[EntrySizeV2-1]

	le := binary.LittleEndian
	offset := 0

	// Node 1: CommDS (32 bytes)
	copy(slice[offset:], sd.CommDs[:])
	offset += merkletree.NodeSize

	// Node 2: Offset (8 bytes) + NumEntries (8 bytes) + RawSize (8 bytes, 62 bits used) + Multicodec (8 bytes)
	le.PutUint64(slice[offset:], sd.Offset)
	offset += 8
	le.PutUint64(slice[offset:], sd.Size)
	offset += 8
	// RawSize: only 62 bits, mask upper 2 bits
	le.PutUint64(slice[offset:], sd.RawSize&0x3FFFFFFFFFFFFFFF)
	offset += 8
	le.PutUint64(slice[offset:], sd.Multicodec)
	offset += 8

	// Node 3: MulticodecDependent (32 bytes)
	copy(slice[offset:], sd.MulticodecDependent[:])
	offset += merkletree.NodeSize

	// Node 4: ACLType (1 byte) + ACLData (8 bytes) + Reserved (7 bytes) + Checksum (16 bytes)
	slice[offset] = sd.ACLType
	offset += 1
	le.PutUint64(slice[offset:], sd.ACLData)
	offset += 8
	copy(slice[offset:], sd.Reserved[:])
	offset += 7
	copy(slice[offset:], sd.Checksum[:])
}

// IntoNodes converts the SegmentDescV2 directly into 4 Merkle nodes without intermediate allocation
// This avoids the overhead of SerializeFr32() which allocates a 256-byte buffer
func (sd SegmentDescV2) IntoNodes() [4]merkletree.Node {
	var nodes [4]merkletree.Node
	le := binary.LittleEndian

	// Node 1: CommDS (32 bytes) - direct copy
	nodes[0] = sd.CommDs

	// Node 2: Offset (8) + Size (8) + RawSize (8, 62 bits) + Multicodec (8) = 32 bytes
	var node2 [32]byte
	le.PutUint64(node2[0:], sd.Offset)
	le.PutUint64(node2[8:], sd.Size)
	le.PutUint64(node2[16:], sd.RawSize&0x3FFFFFFFFFFFFFFF) // Mask to 62 bits
	le.PutUint64(node2[24:], sd.Multicodec)
	nodes[1] = merkletree.Node(node2)

	// Node 3: MulticodecDependent (32 bytes) - direct copy
	nodes[2] = sd.MulticodecDependent

	// Node 4: ACLType (1) + ACLData (8) + Reserved (7) + Checksum (16) = 32 bytes
	var node4 [32]byte
	node4[0] = sd.ACLType
	le.PutUint64(node4[1:], sd.ACLData)
	copy(node4[9:], sd.Reserved[:])
	copy(node4[16:], sd.Checksum[:])
	nodes[3] = merkletree.Node(node4)

	return nodes
}

// NodesPerEntry returns the number of Merkle nodes this entry should use in the tree
// V1 format uses 2 nodes, V2 format uses 4 nodes
// This method checks if the entry looks like it was converted from V1 (all V2-specific fields are zero/default)
func (sd SegmentDescV2) NodesPerEntry() int {
	// Check if this looks like a V1 entry converted to V2:
	// - MulticodecDependent is zero
	// - ACLType is 0
	// - ACLData is 0
	// - Reserved is all zeros
	// - RawSize == Size (typical for V1 compatibility)
	var zeroNode merkletree.Node
	if sd.MulticodecDependent == zeroNode &&
		sd.ACLType == 0 &&
		sd.ACLData == 0 &&
		sd.Reserved == [7]byte{} &&
		sd.RawSize == sd.Size {
		// Likely a V1 entry converted to V2, use 2 nodes
		return 2
	}
	// V2 format uses 4 nodes
	return 4
}

func (sd SegmentDescV2) Validate() error {
	// Validate checksum
	if sd.computeChecksum() != sd.Checksum {
		return validationError("computed checksum does not match embedded checksum")
	}

	// Validate RawSize <= NumEntries
	if sd.RawSize > sd.Size {
		return validationError("rawSize must be <= size")
	}

	// Validate Multicodec (must be supported: Raw or CAR)
	if sd.Multicodec != MulticodecRaw && sd.Multicodec != MulticodecCAR {
		return validationError("multicodec must be 0x55 (Raw) or 0x0202 (CAR)")
	}

	// Validate MulticodecDependent is zero for Raw and CAR codecs
	var zeroNode merkletree.Node
	if sd.MulticodecDependent != zeroNode {
		return validationError("multicodecDependent must be zero for Raw and CAR codecs")
	}

	// Validate ACLType and ACLData
	if sd.ACLType == 0 {
		if sd.ACLData != 0 {
			return validationError("aclData must be zero when aclType is 0")
		}
	}

	// Validate Reserved field is zero
	for i := range sd.Reserved {
		if sd.Reserved[i] != 0 {
			return validationError("reserved field must be zero")
		}
	}

	// Note: Offset and NumEntries alignment checks removed for v2 as flexible alignment is allowed
	// The specification recommends 127-byte alignment but allows arbitrary alignment

	return nil
}

// ==============================

// MakeNode converts SegmentDescV2 to 4 Merkle nodes
// Optimized to use IntoNodes() directly, avoiding intermediate buffer allocation
func (ds SegmentDescV2) MakeNode() (merkletree.Node, merkletree.Node, merkletree.Node, merkletree.Node, error) {
	nodes := ds.IntoNodes()
	return nodes[0], nodes[1], nodes[2], nodes[3], nil
}
func MakeDataSegmentIdxWithChecksum(commDs *fr32.Fr32, offset uint64, size uint64, checksum *[ChecksumSize]byte) (SegmentDescV2, error) {
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
		Checksum:            *checksum,
	}
	if err := en.Validate(); err != nil {
		return SegmentDescV2{}, xerrors.Errorf("input does not form a valid SegmentDescV2: %w", err)
	}
	return en, nil
}

func MakeDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, size uint64) (*SegmentDescV2, error) {
	return MakeDataSegmentIndexEntryV2(CommP, offset, size, size, MulticodecRaw)
}

// MakeDataSegmentIndexEntryV2 creates a v2 index entry with all fields
func MakeDataSegmentIndexEntryV2(CommP *fr32.Fr32, offset uint64, size uint64, rawSize uint64, multicodec uint64) (*SegmentDescV2, error) {
	en := SegmentDescV2{
		CommDs:              *(*merkletree.Node)(CommP),
		Offset:              offset,
		Size:                size,
		RawSize:             rawSize,
		Multicodec:          multicodec,
		MulticodecDependent: merkletree.Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [7]byte{},
		Checksum:            [ChecksumSize]byte{},
	}
	en.Checksum = en.computeChecksum()
	return &en, nil
}
