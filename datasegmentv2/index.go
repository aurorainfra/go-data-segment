package datasegmentv2

import (
	"bytes"
	"encoding"
	"io"
	"math"

	"github.com/filecoin-project/go-data-segment/util"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	logging "github.com/ipfs/go-log/v2"
	"github.com/multiformats/go-multihash"
	_ "github.com/multiformats/go-multihash/register/blake3"
	"golang.org/x/xerrors"
)

var indexLog = logging.Logger("datasegment/index")

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

// IndexDataV2 holds the data segment index (v2, CID-based). Each data entry carries
// CommData+Multihash+Multicodec, so the content CID is derivable via entry.DataCID().
// The serialized index ends with a descriptor entry whose CommData is the BLAKE3 hash
// of the preceding serialized index bytes and whose Offset/Size locate the index section.
type IndexDataV2 struct {
	Entries []*SegmentDesc
	Offset  int64
}

var _ PieceIndex = (*IndexDataV2)(nil)

// ParseIndexSection reads the index section from the sector. The sector tail is the
// index. It reads the last 128 bytes (descriptor), uses its Offset and Size to read
// the full index block, verifies the BLAKE3 digest, then unmarshals the data entries.
func (id *IndexDataV2) ParseIndexSection(reader io.ReaderAt, size int64) error {
	indexLog.Infof("parse index section: sector size %v", size)
	if size < int64(EntrySize) {
		return xerrors.Errorf("invalid index section: size %d < EntrySize %d", size, EntrySize)
	}
	lastEntryBuf := make([]byte, EntrySize)
	lastEntryOff := size - int64(EntrySize)
	n, err := reader.ReadAt(lastEntryBuf, lastEntryOff)
	if err != nil && err != io.EOF {
		return xerrors.Errorf("reading last entry at offset %d: %w", lastEntryOff, err)
	}
	if n < EntrySize {
		return xerrors.Errorf("short read for last entry: got %d", n)
	}
	var sentinel SegmentDesc
	if err := sentinel.UnmarshalBinary(lastEntryBuf); err != nil {
		return xerrors.Errorf("unmarshal index descriptor entry: %w", err)
	}
	if err := validateIndexDescriptor(&sentinel, nil); err != nil {
		return xerrors.Errorf("invalid index descriptor entry: %w", err)
	}
	if sentinel.Offset > uint64(size) || sentinel.Size > uint64(size)-sentinel.Offset {
		return xerrors.Errorf("invalid index descriptor: offset=%d size=%d sectorSize=%d", sentinel.Offset, sentinel.Size, size)
	}
	if sentinel.Offset+sentinel.Size != uint64(size) {
		return xerrors.Errorf("invalid index descriptor: offset=%d size=%d does not end at sector size %d", sentinel.Offset, sentinel.Size, size)
	}
	indexOff := int64(sentinel.Offset)
	indexSize := int64(sentinel.Size)
	indexLog.Infof("index section: offset=%v, size=%v", indexOff, indexSize)
	if indexOff < 0 || indexSize < int64(EntrySize) || indexOff+indexSize > size {
		return xerrors.Errorf("invalid index descriptor: offset=%d size=%d sectorSize=%d", indexOff, indexSize, size)
	}
	indexBlock := make([]byte, indexSize)
	n, err = reader.ReadAt(indexBlock, indexOff)
	if err != nil && err != io.EOF {
		return xerrors.Errorf("reading index block at offset %d: %w", indexOff, err)
	}
	if int64(n) < indexSize {
		return xerrors.Errorf("short read for index block: got %d want %d", n, indexSize)
	}
	if err := validateIndexDescriptor(&sentinel, indexBlock[:len(indexBlock)-EntrySize]); err != nil {
		return xerrors.Errorf("invalid index descriptor digest: %w", err)
	}
	return id.UnmarshalBinary(indexBlock)
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

// Search finds the index of a segment by its content CID (codec + multihash + digest).
// Returns -1 if not found.
func (id *IndexDataV2) Search(c cid.Cid) int {
	if !c.Defined() {
		return -1
	}
	dec, err := multihash.Decode(c.Hash())
	if err != nil || len(dec.Digest) > 32 {
		return -1
	}
	digest := dec.Digest
	var wantCommData [32]byte
	copy(wantCommData[:], digest)
	pref := c.Prefix()
	for i, e := range id.Entries {
		if e == nil {
			continue
		}
		if e.Multicodec == pref.Codec && e.Multihash == pref.MhType && bytes.Equal(e.CommData[:], wantCommData[:]) {
			return i
		}
	}
	return -1
}

// SearchByPieceCIDV2 finds the index of a segment by Piece CID v2 (FRC-0069).
// In the CID-based index format only content CID (DataCID) is supported for lookup;
// Piece CID v2 is not supported. This function is kept for compatibility and typically returns -1.
// Deprecated: use Search by content CID (DataCID) instead.
func (id *IndexDataV2) SearchByPieceCIDV2(pieceCIDV2 cid.Cid) int {
	for i, e := range id.Entries {
		if e == nil {
			continue
		}
		c2, err := e.PieceCIDV2()
		if err != nil {
			continue
		}
		if c2.Equals(pieceCIDV2) {
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

// IndexSize returns the serialized size of the index entries plus the descriptor.
func (i *IndexDataV2) IndexSize() uint64 {
	return uint64(i.NumPieces()+1) * uint64(EntrySize)
}

// MarshalBinary produces the index section only: [entry0][entry1]...[descriptor].
// No separate CID mapping section is needed; each entry's CID is derivable via
// entry.DataCID(). The returned bytes are written at sector offset id.Offset.
func (id *IndexDataV2) MarshalBinary() (data []byte, err error) {
	return id.marshalBinaryWithEntryCount(len(id.Entries) + 1)
}

func (id *IndexDataV2) marshalBinaryWithEntryCount(totalEntries int) (data []byte, err error) {
	entriesCnt := len(id.Entries)
	if totalEntries < entriesCnt+1 {
		return nil, xerrors.Errorf("total index entries %d must fit %d data entries plus descriptor", totalEntries, entriesCnt)
	}
	if id.Offset < 0 {
		return nil, xerrors.Errorf("index offset cannot be negative: %d", id.Offset)
	}

	indexSectionLen := EntrySize * totalEntries
	indexSection := make([]byte, indexSectionLen)
	for i, r := range id.Entries {
		if r != nil {
			r.SerializeFr32Into(indexSection[i*EntrySize : (i+1)*EntrySize])
		}
	}
	indexOffset := uint64(id.Offset)
	indexSize := uint64(indexSectionLen)
	payloadLen := indexSectionLen - EntrySize
	descriptor, err := newIndexDescriptor(indexOffset, indexSize, indexSection[:payloadLen])
	if err != nil {
		return nil, err
	}
	descriptorSlice := indexSection[payloadLen:indexSectionLen]
	descriptor.SerializeFr32Into(descriptorSlice)
	return indexSection, nil
}

// UnmarshalBinary parses the index-only layout from MarshalBinary: a sequence of
// SegmentDesc entries with the last one being the index descriptor, which is not
// added to Entries. Zero entries before the descriptor are treated as reserved
// padding and ignored.
func (id *IndexDataV2) UnmarshalBinary(data []byte) error {
	if rem := len(data) % EntrySize; rem != 0 {
		return xerrors.Errorf("index data is not a multiple of EntrySize: %d %% %d != 0", len(data), EntrySize)
	}
	numEntries := len(data) / EntrySize
	if numEntries == 0 {
		return xerrors.Errorf("index data has no entries")
	}
	indexLog.Infof("unmarshaling index: %d raw entries", numEntries)
	var descriptor SegmentDesc
	if err := descriptor.UnmarshalBinary(data[len(data)-EntrySize:]); err != nil {
		return xerrors.Errorf("unmarshal index descriptor entry: %w", err)
	}
	if err := validateIndexDescriptor(&descriptor, data[:len(data)-EntrySize]); err != nil {
		return xerrors.Errorf("invalid index descriptor entry: %w", err)
	}
	if descriptor.Size != uint64(len(data)) {
		return xerrors.Errorf("index descriptor size %d does not match data length %d", descriptor.Size, len(data))
	}
	if descriptor.Offset > math.MaxInt64 {
		return xerrors.Errorf("index descriptor offset overflows int64: %d", descriptor.Offset)
	}

	*id = IndexDataV2{Offset: int64(descriptor.Offset)}
	id.Entries = make([]*SegmentDesc, 0, numEntries-1)
	for i := 0; i < numEntries-1; i++ {
		entryData := data[i*EntrySize : (i+1)*EntrySize]
		if isZeroEntry(entryData) {
			continue
		}
		var entry SegmentDesc
		if err := entry.UnmarshalBinary(entryData); err != nil {
			return xerrors.Errorf("unmarshal entry at index %d: %w", i, err)
		}
		if err := entry.Validate(); err != nil {
			return xerrors.Errorf("entry at index %v is invalid: %v", i, err)
		}
		id.Entries = append(id.Entries, &entry)
	}
	return nil
}

func newIndexDescriptor(indexOffset uint64, indexSize uint64, payload []byte) (*SegmentDesc, error) {
	digest, err := blake3Digest(payload)
	if err != nil {
		return nil, err
	}
	descriptor := NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, digest[:], indexOffset, indexSize)
	descriptor.Size = indexSize
	descriptor.RawSize = indexSize
	return descriptor.WithCodec(MulticodecIdentity).WithUpdatedChecksum(), nil
}

func validateIndexDescriptor(entry *SegmentDesc, payload []byte) error {
	if entry.Multicodec != MulticodecIdentity {
		return xerrors.Errorf("multicodec must be identity (0), got %d", entry.Multicodec)
	}
	if entry.Multihash != MultihashBlake3 {
		return xerrors.Errorf("multihash must be blake3 (%d), got %d", MultihashBlake3, entry.Multihash)
	}
	if entry.Size < EntrySize || entry.Size%EntrySize != 0 {
		return xerrors.Errorf("size must be a positive multiple of EntrySize: %d", entry.Size)
	}
	if entry.RawSize != entry.Size {
		return xerrors.Errorf("raw size must match size: %d != %d", entry.RawSize, entry.Size)
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	if payload != nil {
		digest, err := blake3Digest(payload)
		if err != nil {
			return err
		}
		if !bytes.Equal(entry.CommData[:], digest[:]) {
			return xerrors.Errorf("blake3 digest mismatch")
		}
	}
	return nil
}

func blake3Digest(data []byte) ([32]byte, error) {
	mh, err := multihash.Sum(data, MultihashBlake3, 32)
	if err != nil {
		return [32]byte{}, xerrors.Errorf("computing blake3 multihash: %w", err)
	}
	decoded, err := multihash.Decode(mh)
	if err != nil {
		return [32]byte{}, xerrors.Errorf("decoding blake3 multihash: %w", err)
	}
	if decoded.Code != MultihashBlake3 {
		return [32]byte{}, xerrors.Errorf("unexpected blake3 multihash code: %d", decoded.Code)
	}
	if len(decoded.Digest) != 32 {
		return [32]byte{}, xerrors.Errorf("unexpected blake3 digest length: %d", len(decoded.Digest))
	}
	var digest [32]byte
	copy(digest[:], decoded.Digest)
	return digest, nil
}

func isZeroEntry(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
