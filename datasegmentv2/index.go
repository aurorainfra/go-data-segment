package datasegmentv2

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"io"

	"github.com/filecoin-project/go-data-segment/util"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	logging "github.com/ipfs/go-log/v2"
	"github.com/multiformats/go-multihash"
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

// IndexDataV2 holds the data segment index (v2, CID-based). Each entry carries CommData+Multihash+Multicodec,
// so the content CID is derivable via entry.DataCID(); no separate CidMappings section is needed.
type IndexDataV2 struct {
	Entries []*SegmentDesc
	Offset  int64
}

var _ PieceIndex = (*IndexDataV2)(nil)

// ParseIndexSection reads the index section from the sector. The sector tail is the index only (no separate
// CID mapping section). It reads the last 128 bytes (sentinel), uses its Offset and Size to read the full
// index block, then unmarshals the entries.
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
		return xerrors.Errorf("unmarshal sentinel entry: %w", err)
	}
	if sentinel.Multicodec != uint64(MulticodeIndexFooter) {
		return xerrors.Errorf("last entry is not index section descriptor (multicodec=%d)", sentinel.Multicodec)
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

// Search finds the index of a segment by its content CID (multihash + digest).
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
		if e.Multihash == pref.MhType && bytes.Equal(e.CommData[:], wantCommData[:]) {
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

// IndexSize returns the size of the index. Defined to be number of entries * EntrySize (128 bytes for v2).
func (i *IndexDataV2) IndexSize() uint64 {
	return uint64(i.NumPieces()) * uint64(EntrySize)
}

// MarshalBinary produces the index section only: [entry0][entry1]...[sentinel]. No separate CID mapping section;
// each entry's CID is derivable via entry.DataCID(). The returned bytes are written at sector offset id.Offset.
func (id *IndexDataV2) MarshalBinary() (data []byte, err error) {
	entriesCnt := len(id.Entries)
	indexSectionLen := EntrySize * (entriesCnt + 1)
	indexSection := make([]byte, indexSectionLen)
	for i, r := range id.Entries {
		if r != nil {
			r.SerializeFr32Into(indexSection[i*EntrySize : (i+1)*EntrySize])
		}
	}
	indexOffset := uint64(id.Offset)
	indexSize := uint64(indexSectionLen)
	sentinel := NewDataSegmentIndexEntryFromMultihash(0, nil, indexOffset, indexSize)
	sentinel.Size = indexSize
	sentinel.RawSize = indexSize
	sentinel.WithCodec(MulticodeIndexFooter).WithUpdatedChecksum()
	sentinelSlice := indexSection[entriesCnt*EntrySize : (entriesCnt+1)*EntrySize]
	sentinel.SerializeFr32Into(sentinelSlice)
	// Ensure Node3 (Offset/Size/RawSize) is written for ParseIndexSection; patch and recompute checksum
	le := binary.LittleEndian
	le.PutUint64(sentinelSlice[72:], indexOffset)
	le.PutUint64(sentinelSlice[80:], indexSize)
	le.PutUint64(sentinelSlice[88:], indexSize&0x3FFFFFFFFFFFFFFF)
	var sentinelDec SegmentDesc
	if err := sentinelDec.UnmarshalBinary(sentinelSlice); err != nil {
		return nil, err
	}
	cs := sentinelDec.computeChecksum()
	copy(sentinelSlice[112:], cs[:])
	return indexSection, nil
}

// UnmarshalBinary parses the index-only layout from MarshalBinary: a sequence of SegmentDesc entries,
// with the last one being the index section descriptor (MulticodeIndexFooter), which is not added to Entries.
func (id *IndexDataV2) UnmarshalBinary(data []byte) error {
	if rem := len(data) % EntrySize; rem != 0 {
		return xerrors.Errorf("index data is not a multiple of EntrySize: %d %% %d != 0", len(data), EntrySize)
	}
	numEntries := len(data) / EntrySize
	if numEntries == 0 {
		return xerrors.Errorf("index data has no entries")
	}
	indexLog.Infof("unmarshaling index: %d raw entries", numEntries)
	*id = IndexDataV2{}
	id.Entries = make([]*SegmentDesc, 0, numEntries-1)
	for i := 0; i < numEntries; i++ {
		var entry SegmentDesc
		if err := entry.UnmarshalBinary(data[i*EntrySize : (i+1)*EntrySize]); err != nil {
			return xerrors.Errorf("unmarshal entry at index %d: %w", i, err)
		}
		if entry.Multicodec == uint64(MulticodeIndexFooter) {
			continue
		}
		if err := entry.Validate(); err != nil {
			return xerrors.Errorf("entry at index %v is invalid: %v", i, err)
		}
		id.Entries = append(id.Entries, &entry)
	}
	return nil
}
