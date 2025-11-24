package index

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"golang.org/x/xerrors"
)

const ChecksumSize = 16

// EntrySizeV1 is the size of a Data Segment Index Entry v1
// v1 entries consist of 2 Merkle nodes (2 * 32 = 64 bytes)
// This is the serialized size in memory (padded format, aligned to 128-byte boundaries).
const EntrySizeV1 = 2 * merkletree.NodeSize // 64 bytes (2 nodes of 32 bytes each)

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

// ToV2 converts a V1 segment description to V2 format
func (sd SegmentDescV1) ToV2() SegmentDescV2 {
	return *NewDataSegmentIndexEntry((*fr32.Fr32)(&sd.CommDs), sd.Offset, sd.Size)
}

var _ encoding.BinaryMarshaler = SegmentDescV1{}
var _ encoding.BinaryUnmarshaler = (*SegmentDescV1)(nil)

func (sd SegmentDescV1) MarshalBinary() ([]byte, error) {
	return sd.SerializeFr32(), nil
}

func (sd *SegmentDescV1) UnmarshalBinary(data []byte) error {
	if len(data) != EntrySizeV1 {
		return xerrors.Errorf("invalid v1 segment description size: expected %d, got %d", EntrySizeV1, len(data))
	}
	le := binary.LittleEndian

	*sd = SegmentDescV1{}
	// Node 1: CommDS (32 bytes)
	sd.CommDs = *(*merkletree.Node)(data[:merkletree.NodeSize])

	// Node 2: Offset (8 bytes) + Size (8 bytes) + Checksum (16 bytes)
	offset := merkletree.NodeSize
	sd.Offset = le.Uint64(data[offset:])
	offset += 8
	sd.Size = le.Uint64(data[offset:])
	offset += 8
	copy(sd.Checksum[:], data[offset:offset+ChecksumSize])

	return nil
}

func (sd SegmentDescV1) SerializeFr32() []byte {
	res := make([]byte, EntrySizeV1)
	sd.SerializeFr32Into(res)
	return res
}

// SerializeFr32Into serializes the V1 Segment Description into given slice
// Panics if len(slice) < EntrySizeV1
func (sd SegmentDescV1) SerializeFr32Into(slice []byte) {
	_ = slice[EntrySizeV1-1]

	le := binary.LittleEndian
	offset := 0

	// Node 1: CommDS (32 bytes)
	copy(slice[offset:], sd.CommDs[:])
	offset += merkletree.NodeSize

	// Node 2: Offset (8 bytes) + Size (8 bytes) + Checksum (16 bytes)
	le.PutUint64(slice[offset:], sd.Offset)
	offset += 8
	le.PutUint64(slice[offset:], sd.Size)
	offset += 8
	copy(slice[offset:], sd.Checksum[:])
}

func (sd SegmentDescV1) computeChecksum() [ChecksumSize]byte {
	sdCopy := sd
	sdCopy.Checksum = [ChecksumSize]byte{}

	toHash := sdCopy.SerializeFr32()
	digest := sha256.Sum256(toHash)
	res := digest[:ChecksumSize]
	// Truncate to 126 bits
	res[ChecksumSize-1] &= 0b00111111
	return *(*[ChecksumSize]byte)(res)
}

func (sd SegmentDescV1) Validate() error {
	// Validate checksum
	if sd.computeChecksum() != sd.Checksum {
		return validationError("computed checksum does not match embedded checksum")
	}
	return nil
}
