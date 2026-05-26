package datasegmentv2

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	cbg "github.com/whyrusleeping/cbor-gen"
	"golang.org/x/xerrors"
)

const ChecksumSize = 16

const NodesPerEntry = 4

// EntrySize is the size of a Data Segment Index Entry v2
// v2 entries consist of 4 Merkle nodes (4 * 32 = 128 bytes)
// This is the serialized size in memory (padded format, aligned to 128-byte boundaries).
const EntrySize = NodesPerEntry * merkletree.NodeSize // 128 bytes (4 nodes of 32 bytes each)

// Multicodec values
const (
	MulticodecIdentity = 0x00   // Identity codec, used by the index descriptor entry
	MulticodecRaw      = 0x55   // Raw binary data
	MulticodecCAR      = 0x0202 // CAR format (IPLD)
)

// Multihash codes (multicodec table)
const (
	MultihashBlake3 = multihash.BLAKE3 // BLAKE3-256, 32-byte digest
)

// SegmentDesc contains a data segment description (v2 format, CID-based).
// Entry layout per FIPs #1216 alternate: Node1=CommData (254 bits), Node2=Multicodec|Multihash|Reserved|2 bits of CommData,
// Node3=Reserved|Offset|Size|RawSize, Node4=ACL|Checksum. CommData is the multihash digest (e.g. 32-byte BLAKE3).
// All offset and size fields represent pre-Fr32-padding byte positions and lengths.
type SegmentDesc struct {
	// node 1
	CommData [32]byte // 256-bit multihash digest; 254 bits in Node1, last 2 bits in Node2

	// node 2
	Multihash  uint64 // multihash code (e.g. 0x1e for blake3)
	Multicodec uint64
	// 124 bits reserved in node2

	// node 3
	Node3Reserved uint64 // 64 bits reserved in Node 3
	Offset        uint64 // pre-Fr32-padding offset from start of deal
	Size          uint64 // total size including trailing padding (pre-Fr32-padding)
	RawSize       uint64 // actual data size before padding (62 bits in spec, stored as uint64)

	// node 4
	ACLType  uint8
	ACLData  uint64
	Reserved [14]byte
	Checksum [ChecksumSize]byte
}

// DataCID returns the content CID this entry represents (from Multicodec + Multihash + CommData).
// This is the client-known CID used for retrieval in the CID-based index format.
func (sd SegmentDesc) DataCID() (cid.Cid, error) {
	return cidFromMultihash(sd.Multicodec, sd.Multihash, sd.CommData[:])
}

// PieceCID returns the content CID (same as DataCID) for compatibility.
// Panics if the entry cannot form a valid CID (e.g. zero Multihash with empty digest).
func (sd SegmentDesc) PieceCID() cid.Cid {
	c, err := sd.DataCID()
	if err != nil {
		panic("SegmentDesc.PieceCID: " + err.Error())
	}
	return c
}

// PieceCIDV2 is not supported in the CID-based index format (no CommP stored).
func (sd SegmentDesc) PieceCIDV2() (cid.Cid, error) {
	return cid.Undef, xerrors.Errorf("PieceCIDV2 not supported in CID-based index format")
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
	subtreeIndex := leafIndex >> height
	var comm merkletree.Node
	copy(comm[:], sd.CommData[:])
	res := merkletree.CommAndLoc{
		Comm: comm,
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
	// V1 used CommDs; store as CommData with multihash 0 (legacy)
	return NewDataSegmentIndexEntryFromMultihash(0, sd.CommDs[:], sd.Offset, sd.Size).WithUpdatedChecksum()
}

// cidFromMultihash builds a CID from content codec, multihash code, and digest.
func cidFromMultihash(codec uint64, mhCode uint64, digest []byte) (cid.Cid, error) {
	if mhCode == 0 && len(digest) == 0 {
		return cid.Undef, xerrors.Errorf("cannot build CID from zero multihash and empty digest")
	}
	mh, err := multihash.Encode(digest, mhCode)
	if err != nil {
		return cid.Undef, err
	}
	return cid.NewCidV1(codec, mh), nil
}

// computeSizeFromRawSize returns the minimum Size (pre-Fr32) that contains rawSize after Fr32 padding.
func computeSizeFromRawSize(rawSize uint64) uint64 {
	minPostFr32Size := rawSize
	if minPostFr32Size%merkletree.NodeSize != 0 {
		minPostFr32Size = ((minPostFr32Size / merkletree.NodeSize) + 1) * merkletree.NodeSize
	}
	size := (minPostFr32Size*127 + 126) / 128
	if size < rawSize {
		size = rawSize
	}
	return size
}

// NewDataSegmentIndexEntryFromCID creates a SegmentDesc from a content CID (multicodec + multihash + digest).
// Digest is copied into CommData (padded or truncated to 32 bytes). Max digest length 32 bytes.
func NewDataSegmentIndexEntryFromCID(c cid.Cid, offset uint64, rawSize uint64) (*SegmentDesc, error) {
	if !c.Defined() {
		return nil, xerrors.Errorf("CID is undefined")
	}
	dec, err := multihash.Decode(c.Hash())
	if err != nil {
		return nil, xerrors.Errorf("decode CID multihash: %w", err)
	}
	digest := dec.Digest
	if len(digest) > 32 {
		return nil, xerrors.Errorf("CID digest longer than 32 bytes")
	}
	var commData [32]byte
	copy(commData[:], digest)
	pref := c.Prefix()
	sd := NewDataSegmentIndexEntryFromMultihash(pref.MhType, commData[:], offset, rawSize)
	sd.Multicodec = pref.Codec
	return sd, nil
}

// NewDataSegmentIndexEntryFromMultihash creates a SegmentDesc from multihash code and digest.
// If digest is nil or empty, CommData is zeroed.
func NewDataSegmentIndexEntryFromMultihash(multihashCode uint64, digest []byte, offset uint64, rawSize uint64) *SegmentDesc {
	var commData [32]byte
	if len(digest) > 0 {
		copy(commData[:], digest)
		if len(digest) < 32 {
			// zero-pad rest
		}
	}
	size := computeSizeFromRawSize(rawSize)
	return &SegmentDesc{
		CommData:   commData,
		Multihash:  multihashCode,
		Multicodec: MulticodecRaw,
		Offset:     offset,
		Size:       size,
		RawSize:    rawSize,
	}
}

// NewDataSegmentIndexEntry creates a legacy CommP-style entry with the given offset and size.
// CommData and Multihash are zero. Deprecated for data segments; use FromCID or FromMultihash.
func NewDataSegmentIndexEntry(CommP *fr32.Fr32, offset uint64, rawSize uint64) *SegmentDesc {
	if CommP == nil {
		return NewDataSegmentIndexEntryFromMultihash(0, nil, offset, rawSize)
	}
	return NewDataSegmentIndexEntryFromMultihash(0, (*CommP)[:], offset, rawSize)
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

	// Node 1: CommData 254 bits (31 bytes + low 6 bits of byte 31)
	copy(sd.CommData[:], data[:32])
	sd.CommData[31] &= 0x3F // keep only Fr32-safe low 6 bits in Node1

	// Node 2: Multicodec (64) | Multihash (64) | Reserved (124 bits) | top 2 bits of CommData
	off := merkletree.NodeSize
	sd.Multicodec = le.Uint64(data[off:])
	off += 8
	sd.Multihash = le.Uint64(data[off:])
	off += 8
	// bytes 16-30 reserved; byte 31 of Node2: low 2 bits = CommData top 2 bits
	sd.CommData[31] |= (data[off+15] & 0x03) << 6
	off += 16                     // skip to end of Node2 (off was 48, 48+16=64)
	off = 2 * merkletree.NodeSize // start of Node3

	// Node 3: Node3Reserved (64) | Offset (64) | Size (64) | RawSize (62 bits)
	sd.Node3Reserved = le.Uint64(data[off:])
	off += 8
	sd.Offset = le.Uint64(data[off:])
	off += 8
	sd.Size = le.Uint64(data[off:])
	off += 8
	sd.RawSize = le.Uint64(data[off:]) & 0x3FFFFFFFFFFFFFFF // 62 bits
	off += 8

	// Node 4: ACLType (8) | ACLData (64) | Reserved (56) | Checksum (126)
	sd.ACLType = data[off]
	off += 1
	sd.ACLData = le.Uint64(data[off:])
	off += 8
	copy(sd.Reserved[7:], data[off:off+7])
	off += 7
	copy(sd.Checksum[:], data[off:off+ChecksumSize])
	// Normalize to 126 bits so validation matches computeChecksum() (which truncates)
	sd.Checksum[ChecksumSize-1] &= 0x3F
	return nil
}

func (sd *SegmentDesc) SerializeFr32() []byte {
	res := make([]byte, EntrySize)
	sd.SerializeFr32Into(res)
	return res
}

// SerializeFr32Into serializes the SegmentDesc into the given slice (CID-based layout).
// Panics if len(slice) < EntrySize.
func (sd *SegmentDesc) SerializeFr32Into(slice []byte) {
	_ = slice[EntrySize-1]
	le := binary.LittleEndian
	off := 0

	// Node 1: CommData 254 bits (31 bytes + low 6 bits of byte 31)
	copy(slice[off:], sd.CommData[:])
	slice[off+31] &= 0x3F // clear top 2 bits in serialized Node1 for Fr32 stability
	off += merkletree.NodeSize

	// Node 2: Multicodec (64) | Multihash (64) | Reserved (15 bytes) | top 2 bits = CommData[31]>>6
	le.PutUint64(slice[off:], sd.Multicodec)
	off += 8
	le.PutUint64(slice[off:], sd.Multihash)
	off += 8
	// bytes 16-30 zero; byte 31 low bits = top 2 bits of CommData
	slice[off+15] = sd.CommData[31] >> 6
	off += 16 // skip to end of Node 2 (bytes 48-63 reserved), so Node 3 starts at 64

	// Node 3: Node3Reserved (64) | Offset (64) | Size (64) | RawSize (62 bits)
	le.PutUint64(slice[off:], sd.Node3Reserved)
	off += 8
	le.PutUint64(slice[off:], sd.Offset)
	off += 8
	le.PutUint64(slice[off:], sd.Size)
	off += 8
	le.PutUint64(slice[off:], sd.RawSize&0x3FFFFFFFFFFFFFFF)
	off += 8

	// Node 4: ACLType (8) | ACLData (64) | Reserved (56) | Checksum (126)
	slice[off] = sd.ACLType
	off += 1
	le.PutUint64(slice[off:], sd.ACLData)
	off += 8
	copy(slice[off:], sd.Reserved[7:])
	off += 7
	copy(slice[off:], sd.Checksum[:])
}

// IntoNodes converts the SegmentDesc directly into 4 Merkle nodes (CID-based layout).
func (sd *SegmentDesc) IntoNodes() [4]merkletree.Node {
	var nodes [NodesPerEntry]merkletree.Node
	le := binary.LittleEndian

	// Node 1: CommData 254 bits
	var n1 [32]byte
	copy(n1[:], sd.CommData[:])
	n1[31] &= 0x3F
	nodes[0] = merkletree.Node(n1)

	// Node 2: Multicodec | Multihash | Reserved | last 2 bits of CommData
	var node2 [32]byte
	le.PutUint64(node2[0:], sd.Multicodec)
	le.PutUint64(node2[8:], sd.Multihash)
	node2[31] = sd.CommData[31] >> 6
	nodes[1] = merkletree.Node(node2)

	// Node 3: Node3Reserved | Offset | Size | RawSize (62 bits)
	var node3 [32]byte
	le.PutUint64(node3[0:], sd.Node3Reserved)
	le.PutUint64(node3[8:], sd.Offset)
	le.PutUint64(node3[16:], sd.Size)
	le.PutUint64(node3[24:], sd.RawSize&0x3FFFFFFFFFFFFFFF)
	nodes[2] = merkletree.Node(node3)

	// Node 4: ACLType | ACLData | Reserved | Checksum
	var node4 [32]byte
	node4[0] = sd.ACLType
	le.PutUint64(node4[1:], sd.ACLData)
	copy(node4[9:], sd.Reserved[7:])
	copy(node4[16:], sd.Checksum[:])
	nodes[3] = merkletree.Node(node4)
	return nodes
}

func (sd *SegmentDesc) WithCodec(codec uint64) *SegmentDesc {
	sd.Multicodec = codec
	return sd
}

func (sd *SegmentDesc) WithACL(t uint8, data uint64) *SegmentDesc {
	sd.ACLType = t
	sd.ACLData = data
	return sd
}

func (sd *SegmentDesc) Validate() error {
	// Validate checksum (compare normalized: computed is 126-bit, normalize stored for comparison)
	computed := sd.computeChecksum()
	var stored [ChecksumSize]byte
	copy(stored[:], sd.Checksum[:])
	stored[ChecksumSize-1] &= 0x3F
	if computed != stored {
		return validationError("computed checksum does not match embedded checksum")
	}

	// Validate RawSize does not exceed Size
	if sd.RawSize > sd.Size {
		return validationError("rawSize must be <= size")
	}

	// For v2, Size doesn't need to be power-of-two aligned
	// We only validate that Size is at least RawSize and aligned to NodeSize boundaries
	// (which is already ensured by NewDataSegmentIndexEntry)

	// Validate Multicodec (must be supported: Identity, Raw, or CAR)
	if sd.Multicodec != MulticodecIdentity && sd.Multicodec != MulticodecRaw && sd.Multicodec != MulticodecCAR {
		return validationError("multicodec must be 0x00 (Identity), 0x55 (Raw), or 0x0202 (CAR)")
	}

	// Node3Reserved must be zero.
	if sd.Node3Reserved != 0 {
		return validationError("node3Reserved must be zero")
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

// CBOR array length: 11 fields for v2 (CommData, Offset, Size, RawSize, Multicodec, Multihash, Node3Reserved, ACLType, ACLData, Reserved, Checksum)
var lengthBufSegmentDesc = []byte{0x8b}

func (t *SegmentDesc) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if _, err := cw.Write(lengthBufSegmentDesc); err != nil {
		return err
	}

	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(t.CommData))); err != nil {
		return err
	}
	if _, err := cw.Write(t.CommData[:]); err != nil {
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
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Multihash)); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajUnsignedInt, uint64(t.Node3Reserved)); err != nil {
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
	if numFields != 5 && numFields != 11 {
		return fmt.Errorf("cbor input had wrong number of fields (expected 5 or 11, got %d)", numFields)
	}

	// t.CommData (32 bytes)

	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}

	if extra > cbg.ByteArrayMaxLen {
		return fmt.Errorf("t.CommData: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString {
		return fmt.Errorf("expected byte array")
	}

	if extra != 32 {
		return fmt.Errorf("expected CommData to have 32 elements")
	}

	if _, err := io.ReadFull(cr, t.CommData[:]); err != nil {
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

	// Legacy 5-field format: 5th field is Checksum; then set v2 defaults and return
	if numFields == 5 {
		maj, extra, err = cr.ReadHeader()
		if err != nil {
			return err
		}
		if extra > cbg.ByteArrayMaxLen {
			return fmt.Errorf("t.Checksum: byte array too large (%d)", extra)
		}
		if maj != cbg.MajByteString || extra != 16 {
			return fmt.Errorf("expected 16-byte checksum")
		}
		if _, err := io.ReadFull(cr, t.Checksum[:]); err != nil {
			return err
		}
		t.Multicodec = MulticodecRaw
		return nil
	}

	// 11-field v2 format: Multicodec, Multihash, Node3Reserved, ACLType, ACLData, Reserved, Checksum
	// t.Multicodec
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for multicodec")
	}
	t.Multicodec = uint64(extra)
	// t.Multihash
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for multihash")
	}
	t.Multihash = uint64(extra)
	// t.Node3Reserved
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if maj != cbg.MajUnsignedInt {
		return fmt.Errorf("wrong type for node3Reserved")
	}
	t.Node3Reserved = uint64(extra)
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
	// t.Checksum (16 bytes)
	maj, extra, err = cr.ReadHeader()
	if err != nil {
		return err
	}
	if extra > cbg.ByteArrayMaxLen {
		return fmt.Errorf("t.Checksum: byte array too large (%d)", extra)
	}
	if maj != cbg.MajByteString || extra != 16 {
		return fmt.Errorf("expected 16-byte checksum")
	}
	if _, err := io.ReadFull(cr, t.Checksum[:]); err != nil {
		return err
	}
	return nil
}
