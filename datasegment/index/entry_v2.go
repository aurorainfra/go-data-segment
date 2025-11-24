package index

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"fmt"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"
	"io"
)

const NodesPerEntry = 4

// EntrySizeV2 is the size of a Data Segment Index Entry v2
// v2 entries consist of 4 Merkle nodes (4 * 32 = 128 bytes)
// This is the serialized size in memory (padded format, aligned to 128-byte boundaries).
const EntrySizeV2 = NodesPerEntry * merkletree.NodeSize // 128 bytes (4 nodes of 32 bytes each)

// Multicodec values
const (
	MulticodecRaw = 0x55   // Raw binary data
	MulticodecCAR = 0x0202 // CAR format (IPLD)
)

// SegmentDescV2 contains a data segment description (v2 format)
// to be contained as four Fr32 elements in 4 leaf nodes of the data segment index
type SegmentDescV2 struct {
	CommDs merkletree.Node
	Offset uint64

	Height  uint8 // tree height (number of levels from leaves to root)
	RawSize uint64

	Multicodec          uint64
	MulticodecDependent merkletree.Node
	ACLType             uint8
	ACLData             uint64
	Reserved            [14]byte
	Checksum            [ChecksumSize]byte
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
	size := sd.Size()
	return size - size/128
}

func pieceSize2Height(size uint64) uint8 {
	paddedSize := size * 128 / 127
	leafCnt := paddedSize / merkletree.NodeSize
	return uint8(util.Log2Ceil(leafCnt))
}

func (sd SegmentDescV2) CommAndLoc() merkletree.CommAndLoc {
	lvl := util.Log2Ceil(sd.Size() / merkletree.NodeSize)
	res := merkletree.CommAndLoc{
		Comm: sd.CommDs,
		Loc: merkletree.Location{
			Level: lvl,
			Index: sd.Offset / merkletree.NodeSize >> lvl,
		},
	}
	return res
}

func (sd *SegmentDescV2) Size() uint64 {
	if sd.Height == 0 {
		return sd.RawSize
	}
	return uint64(merkletree.NodeSize) << sd.Height
}

// create a new SegmentDescV2
// the size should be a pre-fr32-padding one containing tail null paddings
func NewDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, size uint64) *SegmentDescV2 {
	height := pieceSize2Height(size)
	return (&SegmentDescV2{
		CommDs:              *(*merkletree.Node)(CommP),
		Offset:              offset,
		Height:              height,
		RawSize:             size, // TODO
		Multicodec:          MulticodecRaw,
		MulticodecDependent: merkletree.Node{},
		ACLType:             0,
		ACLData:             0,
		Reserved:            [14]byte{},
		Checksum:            [ChecksumSize]byte{},
	}).withUpdatedChecksum()
}

func (sd *SegmentDescV2) computeChecksum() [ChecksumSize]byte {
	sdCopy := sd
	sdCopy.Checksum = [ChecksumSize]byte{}

	toHash := sdCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:ChecksumSize]
	// Truncate to  126 bits
	res[ChecksumSize-1] &= 0b00111111
	return *(*[ChecksumSize]byte)(res)
}

func (sd *SegmentDescV2) withUpdatedChecksum() *SegmentDescV2 {
	sd.Checksum = sd.computeChecksum()
	return sd
}

var _ encoding.BinaryMarshaler = &SegmentDescV2{}
var _ encoding.BinaryUnmarshaler = (*SegmentDescV2)(nil)

func (sd *SegmentDescV2) MarshalBinary() ([]byte, error) {
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

	// Node 2 layout:
	// Offset (8 bytes) | Height (1 byte) | Reserved[0:7] (7 bytes) | Padding (8 bytes) | Multicodec (8 bytes)
	offset := merkletree.NodeSize
	sd.Offset = le.Uint64(data[offset:])
	offset += 8
	sd.Height = data[offset]
	offset += 1
	copy(sd.Reserved[:7], data[offset:offset+7])
	offset += 7
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

func (sd *SegmentDescV2) SerializeFr32() []byte {
	res := make([]byte, EntrySizeV2)
	sd.SerializeFr32Into(res)
	return res
}

// SerializeFr32Into serializes the Segment Desctipion into given slice
// Panics if len(slice) < EntrySizeV2
func (sd *SegmentDescV2) SerializeFr32Into(slice []byte) {
	_ = slice[EntrySizeV2-1]

	le := binary.LittleEndian
	offset := 0

	// Node 1: CommDS (32 bytes)
	copy(slice[offset:], sd.CommDs[:])
	offset += merkletree.NodeSize

	// Node 2 layout matches UnmarshalBinary
	le.PutUint64(slice[offset:], sd.Offset)
	offset += 8
	slice[offset] = sd.Height
	offset += 1
	copy(slice[offset:], sd.Reserved[:7])
	offset += 7
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

// IntoNodes converts the SegmentDescV2 directly into 4 Merkle nodes without intermediate allocation
// This avoids the overhead of SerializeFr32() which allocates a 256-byte buffer
func (sd *SegmentDescV2) IntoNodes() [4]merkletree.Node {
	var nodes [NodesPerEntry]merkletree.Node
	le := binary.LittleEndian

	// Node 1: CommDS (32 bytes) - direct copy
	nodes[0] = sd.CommDs

	var node2 [32]byte
	le.PutUint64(node2[0:], sd.Offset)
	node2[8] = sd.Height
	copy(node2[9:16], sd.Reserved[:7])
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

func (sd *SegmentDescV2) Validate() error {
	// Validate checksum
	if sd.computeChecksum() != sd.Checksum {
		return validationError("computed checksum does not match embedded checksum")
	}

	// Validate padding does not exceed total size
	size := sd.Size()
	if sd.RawSize > size {
		return validationError("padding must be <= size")
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

var lengthBufSegmentDesc = []byte{133}

func (t *SegmentDescV2) MarshalCBOR(w io.Writer) error {
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

	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Height)); err != nil {
		return err
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.RawSize)); err != nil {
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

func (t *SegmentDescV2) UnmarshalCBOR(r io.Reader) (err error) {
	*t = SegmentDescV2{}

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

	if extra != 5 {
		return fmt.Errorf("cbor input had wrong number of fields")
	}

	// t.CommDs (merkletree.Node) (array)

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

	// t.Height
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for uint64 field")
	}
	t.Height = uint8(extra)

	// t.Padding
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
	return nil
}
