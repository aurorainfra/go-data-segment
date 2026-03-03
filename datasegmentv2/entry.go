package datasegmentv2

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"fmt"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"golang.org/x/xerrors"

	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
	"io"
)

const ChecksumSize = 16

const NodesPerEntry = 4

// EntrySize is the size of a Data Segment Index Entry v2
// v2 entries consist of 4 Merkle nodes (4 * 32 = 128 bytes)
// This is the serialized size in memory (padded format, aligned to 128-byte boundaries).
const EntrySize = NodesPerEntry * merkletree.NodeSize // 128 bytes (4 nodes of 32 bytes each)

// Multicodec values
const (
	MulticodecRaw = 0x55   // Raw binary data
	MulticodecCAR = 0x0202 // CAR format (IPLD)
)

// SegmentDesc contains a data segment description (v2 format)
// to be contained as four Fr32 elements in 4 leaf nodes of the data segment index
// All offset and size fields represent pre-Fr32-padding byte positions and lengths
type SegmentDesc struct {
	CommDs merkletree.Node
	Offset uint64 // pre-Fr32-padding offset from start of deal

	// Size is the total size including trailing padding (pre-Fr32-padding)
	Size    uint64
	RawSize uint64

	Multicodec          uint64
	MulticodecDependent merkletree.Node
	ACLType             uint8
	ACLData             uint64
	Reserved            [14]byte
	Checksum            [ChecksumSize]byte
}

// PieceCID returns the PieceCID v1 of the sub-deal
func (sd SegmentDesc) PieceCID() cid.Cid {
	c, err := commcid.PieceCommitmentV1ToCID(sd.CommDs[:])
	if err != nil {
		panic("CommDs is always 32 bytes: " + err.Error())
	}
	return c
}

// PieceCIDV2 computes the Piece CID v2 (FRC-0069) for this segment using the index entry's
// CommDs and RawSize, via commcid.DataCommitmentToPieceCidv2.
func (sd SegmentDesc) PieceCIDV2() (cid.Cid, error) {
	return commcid.DataCommitmentToPieceCidv2(sd.CommDs[:], sd.RawSize)
}

// UnpaddedOffset returns unpadded offset of the sub-deal relative to the deal start
// (converts from post-Fr32-padding to pre-Fr32-padding)
func (sd SegmentDesc) UnpaddedOffset() uint64 {
	// Offset is already in pre-Fr32-padding bytes according to v2 spec
	return sd.Offset
}

// UnpaddedLength returns unpadded length of the sub-deal
// This is simply RawSize since all sizes in v2 are pre-Fr32-padding
func (sd SegmentDesc) UnpaddedLength() uint64 {
	return sd.RawSize
}

// Padding returns the amount of padding (Size - RawSize)
func (sd SegmentDesc) Padding() uint64 {
	if sd.Size < sd.RawSize {
		return 0
	}
	return sd.Size - sd.RawSize
}

// Height returns the tree height computed from Size
// Height = log2(ceil(Size / NodeSize))
// For v2, Size doesn't need to be power-of-two, so we use Log2Ceil to get the height
// needed to contain the actual size
func (sd SegmentDesc) Height() uint8 {
	if sd.Size == 0 {
		return 0
	}
	leafCount := sd.Size / merkletree.NodeSize
	if leafCount == 0 {
		return 0
	}
	// For v2, Size doesn't need to be power-of-two
	// We compute the height needed to contain this size (which may not be power-of-two)
	return uint8(util.Log2Ceil(leafCount))
}

func (sd SegmentDesc) CommAndLoc() merkletree.CommAndLoc {
	height := sd.Height()
	lvl := int(height)
	leafIndex := sd.Offset / merkletree.NodeSize
	// For a tree of height h, the root is at level h, and we need to compute the index
	// at that level that contains this leaf
	subtreeIndex := leafIndex >> height
	res := merkletree.CommAndLoc{
		Comm: sd.CommDs,
		Loc: merkletree.Location{
			Level: lvl,
			Index: subtreeIndex,
		},
	}
	return res
}

// SegmentDescV1 contains a data segment description (v1 format)
// to be contained as two Fr32 elements in 2 leaf nodes of the data segment index
type SegmentDescV1 struct {
	// Commitment to the data segment (Merkle node which is the root of the subtree containing all the nodes making up the data segment)
	CommDs merkletree.Node
	// Offset is the offset from the start of the deal in padded bytes
	Offset uint64
	// Size is the number of padded bytes that is contained in the sub-deal reflected by this SegmentDescV1
	Size uint64
	// Checksum is a 126 bit checksum (SHA256) computed on CommDs || Offset || Size
	Checksum [ChecksumSize]byte
}

func NewDataSegmentDescFromV1(sd *SegmentDescV1) *SegmentDesc {
	// For V1, Size is the total size (which in v2 terms would be both Size and RawSize)
	// Since V1 doesn't have padding, we use Size as both Size and RawSize
	return NewDataSegmentIndexEntry((*fr32.Fr32)(&sd.CommDs), sd.Offset, sd.Size).WithUpdatedChecksum()
}

// NewDataSegmentIndexEntry creates a new SegmentDesc entry for v2 format
// Parameters:
//   - CommP: The piece commitment (CommDs)
//   - offset: Pre-Fr32-padding byte offset from start of deal (can be arbitrary, no alignment required)
//   - rawSize: Pre-Fr32-padding actual data size (can be arbitrary, no power-of-two requirement)
//
// The function computes Size (total size including padding) such that:
//   - Size >= RawSize
//   - After Fr32 padding, Size is aligned to NodeSize boundaries
//
// For v2, both offset and size can be arbitrary - no power-of-two alignment is required.
// The piece will be placed at the exact offset specified, and the size will be
// the minimum needed to contain the rawSize data after Fr32 padding.
func NewDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, rawSize uint64) *SegmentDesc {
	// Calculate the minimum post-Fr32 size needed to contain the rawSize data
	// Fr32 padding: post-Fr32 = ceil(pre-Fr32 * 128 / 127)
	// We need: post-Fr32 >= rawSize (to contain the data)
	// And: post-Fr32 should be aligned to NodeSize boundaries

	// Start by computing minimum post-Fr32 size needed
	minPostFr32Size := rawSize
	if minPostFr32Size%merkletree.NodeSize != 0 {
		minPostFr32Size = ((minPostFr32Size / merkletree.NodeSize) + 1) * merkletree.NodeSize
	}

	// Convert back to pre-Fr32 size
	// post-Fr32 = ceil(pre-Fr32 * 128 / 127)
	// So: pre-Fr32 >= (post-Fr32 * 127 + 126) / 128
	// We use the minimum pre-Fr32 size that gives us the required post-Fr32 size
	size := (minPostFr32Size*127 + 126) / 128

	// Ensure Size is at least RawSize (should always be true, but check anyway)
	if size < rawSize {
		size = rawSize
	}

	return &SegmentDesc{
		CommDs:     *(*merkletree.Node)(CommP),
		Offset:     offset,
		Size:       size,
		RawSize:    rawSize,
		Multicodec: MulticodecRaw,
	}
}

func (sd *SegmentDesc) computeChecksum() [ChecksumSize]byte {
	sdCopy := *sd
	sdCopy.Checksum = [ChecksumSize]byte{}

	toHash := sdCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:ChecksumSize]
	// Truncate to  126 bits
	res[ChecksumSize-1] &= 0b00111111
	return *(*[ChecksumSize]byte)(res)
}

func (sd *SegmentDesc) WithUpdatedChecksum() *SegmentDesc {
	sd.Checksum = sd.computeChecksum()
	return sd
}

var _ encoding.BinaryMarshaler = &SegmentDesc{}
var _ encoding.BinaryUnmarshaler = (*SegmentDesc)(nil)

func (sd *SegmentDesc) MarshalBinary() ([]byte, error) {
	return sd.SerializeFr32(), nil
}

func (sd *SegmentDesc) UnmarshalBinary(data []byte) error {
	if len(data) != EntrySize {

		return xerrors.Errorf("invalid segment description size: expected %d, got %d", EntrySize, len(data))
	}
	le := binary.LittleEndian

	*sd = SegmentDesc{}
	// Node 1: CommDS (32 bytes)
	sd.CommDs = *(*merkletree.Node)(data[:merkletree.NodeSize])

	// Node 2 layout (32 bytes = 254 bits usable):
	// Offset (64 bits = 8 bytes) | Size (64 bits = 8 bytes) | RawSize (64 bits = 8 bytes) | Multicodec (64 bits = 8 bytes)
	// Note: FRC-1216 specifies RawSize as 62 bits, but we use 64 bits for simplicity
	offset := merkletree.NodeSize
	sd.Offset = le.Uint64(data[offset:])
	offset += 8
	sd.Size = le.Uint64(data[offset:])
	offset += 8
	sd.RawSize = le.Uint64(data[offset:])
	offset += 8
	sd.Multicodec = le.Uint64(data[offset:])
	offset += 8

	// Node 3: MulticodecDependent (32 bytes)
	sd.MulticodecDependent = *(*merkletree.Node)(data[offset:])
	offset += merkletree.NodeSize

	// Node 4: ACLType (1 byte) + ACLData (8 bytes) + Reserved[7:] (7 bytes) + Checksum (16 bytes)
	sd.ACLType = data[offset]
	offset += 1
	sd.ACLData = le.Uint64(data[offset:])
	offset += 8
	copy(sd.Reserved[7:], data[offset:offset+7])
	offset += 7
	copy(sd.Checksum[:], data[offset:offset+ChecksumSize])

	// Don't validate here - let the caller decide whether to validate
	// This allows unmarshaling invalid entries for testing purposes
	return nil
}

func (sd *SegmentDesc) SerializeFr32() []byte {
	res := make([]byte, EntrySize)
	sd.SerializeFr32Into(res)
	return res
}

// SerializeFr32Into serializes the Segment Desctipion into given slice
// Panics if len(slice) < EntrySize
func (sd *SegmentDesc) SerializeFr32Into(slice []byte) {
	_ = slice[EntrySize-1]

	le := binary.LittleEndian
	offset := 0

	// Node 1: CommDS (32 bytes)
	copy(slice[offset:], sd.CommDs[:])
	offset += merkletree.NodeSize

	// Node 2 layout matches UnmarshalBinary
	le.PutUint64(slice[offset:], sd.Offset)
	offset += 8
	le.PutUint64(slice[offset:], sd.Size)
	offset += 8
	le.PutUint64(slice[offset:], sd.RawSize)
	offset += 8
	le.PutUint64(slice[offset:], sd.Multicodec)
	offset += 8

	// Node 3: MulticodecDependent (32 bytes)
	copy(slice[offset:], sd.MulticodecDependent[:])
	offset += merkletree.NodeSize

	// Node 4: ACLType (1 byte) + ACLData (8 bytes) + Reserved[7:] (7 bytes) + Checksum (16 bytes)
	slice[offset] = sd.ACLType
	offset += 1
	le.PutUint64(slice[offset:], sd.ACLData)
	offset += 8
	copy(slice[offset:], sd.Reserved[7:])
	offset += 7
	copy(slice[offset:], sd.Checksum[:])
}

// IntoNodes converts the SegmentDesc directly into 4 Merkle nodes without intermediate allocation
// This avoids the overhead of SerializeFr32() which allocates a 256-byte buffer
func (sd *SegmentDesc) IntoNodes() [4]merkletree.Node {
	var nodes [NodesPerEntry]merkletree.Node
	le := binary.LittleEndian

	// Node 1: CommDS (32 bytes) - direct copy
	nodes[0] = sd.CommDs

	var node2 [32]byte
	le.PutUint64(node2[0:], sd.Offset)
	le.PutUint64(node2[8:], sd.Size)
	le.PutUint64(node2[16:], sd.RawSize)
	le.PutUint64(node2[24:], sd.Multicodec)
	nodes[1] = merkletree.Node(node2)

	// Node 3: MulticodecDependent (32 bytes) - direct copy
	nodes[2] = sd.MulticodecDependent

	// Node 4 layout
	var node4 [32]byte
	node4[0] = sd.ACLType
	le.PutUint64(node4[1:], sd.ACLData)
	copy(node4[9:], sd.Reserved[7:])
	copy(node4[16:], sd.Checksum[:])
	nodes[3] = merkletree.Node(node4)

	return nodes
}

func (sd *SegmentDesc) WithCodec(codec uint64, codecDependent merkletree.Node) *SegmentDesc {
	sd.Multicodec = codec
	sd.MulticodecDependent = codecDependent
	return sd
}

func (sd *SegmentDesc) WithACL(t uint8, data uint64) *SegmentDesc {
	sd.ACLType = t
	sd.ACLData = data
	return sd
}

func (sd *SegmentDesc) Validate() error {
	// Validate checksum
	if sd.computeChecksum() != sd.Checksum {
		return validationError("computed checksum does not match embedded checksum")
	}

	// Validate RawSize does not exceed Size
	if sd.RawSize > sd.Size {
		return validationError("rawSize must be <= size")
	}

	// For v2, Size doesn't need to be power-of-two aligned
	// We only validate that Size is at least RawSize and aligned to NodeSize boundaries
	// (which is already ensured by NewDataSegmentIndexEntry)

	// Validate Multicodec (must be supported: Raw or CAR)
	if sd.Multicodec != MulticodecRaw && sd.Multicodec != MulticodecCAR {
		return validationError("multicodec must be 0x55 (Raw) or 0x0202 (CAR)")
	}

	// Validate MulticodecDependent: zero for Raw/CAR unless Reserved[7]=1 (Data CID extension).
	// Per FRC-1216, MulticodecDependent is for "multicodec-specific metadata"; when Reserved[7]=1
	// we use it to store the 32-byte digest of the optional Data CID (user-submitted CID for retrieval).
	var zeroNode merkletree.Node
	if sd.MulticodecDependent != zeroNode {
		if sd.Reserved[7] != 1 {
			return validationError("multicodecDependent must be zero for Raw and CAR codecs unless Reserved[7]=1 (Data CID)")
		}
	}

	// Validate ACLType and ACLData
	if sd.ACLType == 0 {
		if sd.ACLData != 0 {
			return validationError("aclData must be zero when aclType is 0")
		}
	}

	// Validate Reserved: [0:7] and [9:14] must be zero; [7] = hasDataCid (0 or 1), [8] = dataCidEncoding (0..3)
	for i := range sd.Reserved {
		if i == 7 {
			if sd.Reserved[7] > 1 {
				return validationError("reserved[7] (hasDataCid) must be 0 or 1")
			}
			continue
		}
		if i == 8 {
			if sd.Reserved[8] > 3 {
				return validationError("reserved[8] (dataCidEncoding) must be 0..3")
			}
			continue
		}
		if sd.Reserved[i] != 0 {
			return validationError("reserved field must be zero except [7] and [8]")
		}
	}

	// Note: Offset and NumPieces alignment checks removed for v2 as flexible alignment is allowed
	// The specification recommends 127-byte alignment but allows arbitrary alignment

	return nil
}

// ==============================

// CBOR array length: 10 fields for v2 (CommDs, Offset, Size, RawSize, Multicodec, MulticodecDependent, ACLType, ACLData, Reserved, Checksum)
var lengthBufSegmentDesc = []byte{0x8a}

func (t *SegmentDesc) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufSegmentDesc); err != nil {
		return err
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.CommDs))); err != nil {
		return err
	}
	if _, err := cw.Write(t.CommDs[:]); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Offset)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Size)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.RawSize)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Multicodec)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.MulticodecDependent))); err != nil {
		return err
	}
	if _, err := cw.Write(t.MulticodecDependent[:]); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.ACLType)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.ACLData)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.Reserved))); err != nil {
		return err
	}
	if _, err := cw.Write(t.Reserved[:]); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.Checksum))); err != nil {
		return err
	}
	if _, err := cw.Write(t.Checksum[:]); err != nil {
		return err
	}
	return nil
}

func (t *SegmentDesc) UnmarshalCBOR(r io.Reader) (err error) {
	*t = SegmentDesc{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajArray {
		return fmt.Errorf("cbor input should be of type array")
	}
	numFields := extra
	if numFields != 5 && numFields != 10 {
		return fmt.Errorf("cbor input had wrong number of fields (expected 5 or 10, got %d)", numFields)
	}

	// t.CommDs (merkletree.Node)

	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > cbg.ByteArrayMaxLen {
		return fmt.Errorf("t.CommDs: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}

	if extra != 32 {
		return fmt.Errorf("expected array to have 32 elements")
	}

	t.CommDs = [32]uint8{}

	if _, err := io.ReadFull(cr, t.CommDs[:]); err != nil {
		return err
	}
	// t.Offset
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for uint64 field")
	}
	t.Offset = uint64(extra)

	// t.Size
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for uint64 field")
	}
	t.Size = uint64(extra)

	// t.RawSize
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for uint64 field")
	}
	t.RawSize = uint64(extra)

	// t.Checksum ([16]uint8)

	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > cbg.ByteArrayMaxLen {
		return fmt.Errorf("t.Checksum: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}

	if extra != 16 {
		return fmt.Errorf("expected array to have 16 elements")
	}

	t.Checksum = [16]uint8{}

	if _, err := io.ReadFull(cr, t.Checksum[:]); err != nil {
		return err
	}
	// Legacy 5-field format: set v2 defaults and return
	if numFields == 5 {
		t.Multicodec = MulticodecRaw
		return nil
	}
	// t.Multicodec
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for multicodec")
	}
	t.Multicodec = uint64(extra)
	// t.MulticodecDependent (32 bytes)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajByteString || extra != 32 {
		return fmt.Errorf("multicodecDependent: expected byte array of 32, got type/len %d/%d", maj, extra)
	}
	if _, err := io.ReadFull(cr, t.MulticodecDependent[:]); err != nil {
		return err
	}
	// t.ACLType
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt || extra > 0xff {
		return fmt.Errorf("wrong type or value for aclType")
	}
	t.ACLType = uint8(extra)
	// t.ACLData
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for aclData")
	}
	t.ACLData = uint64(extra)
	// t.Reserved (14 bytes)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	reservedLen := uint64(len(t.Reserved))
	if maj != cbg.MajByteString || extra > reservedLen {
		return fmt.Errorf("reserved: expected byte array of at most %d", len(t.Reserved))
	}
	n := int(extra)
	if n > 0 {
		if _, err := io.ReadFull(cr, t.Reserved[:n]); err != nil {
			return err
		}
	}
	return nil
}
