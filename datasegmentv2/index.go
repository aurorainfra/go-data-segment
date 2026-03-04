package datasegmentv2

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/ipfs/go-cid"
	logging "github.com/ipfs/go-log/v2"
	"golang.org/x/xerrors"
	"io"
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

type IndexDataV2 struct {
	Entries     []*SegmentDesc
	CidMappings []*cid.Cid
	Offset      int64
}

var _ PieceIndex = (*IndexDataV2)(nil)

// ParseIndexSection reads the index section and CID mapping section from the sector.
// It reads the last entry (must be the MulticodecCIDMappingSection descriptor), uses its Offset and Size
// to read the full [mapping section][index section] block, then calls UnmarshalBinary.
// reader must allow reading from the sector; size is the sector length.
func (id *IndexDataV2) ParseIndexSection(reader io.ReaderAt, size int64) error {
	indexLog.Infof("start to parse index section. size: %v", size)
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
	var lastEntry SegmentDesc
	if err := lastEntry.UnmarshalBinary(lastEntryBuf); err != nil {
		return xerrors.Errorf("unmarshal last entry: %w", err)
	}
	if lastEntry.Multicodec != uint64(MulticodecCIDMappingSection) {
		return xerrors.Errorf("last entry is not CID mapping descriptor (multicodec=%d)", lastEntry.Multicodec)
	}
	mappingOff := int64(lastEntry.Offset)
	mappingSize := int64(lastEntry.Size)
	indexLog.Infof("mapping section: offset=%v, size=%v", mappingOff, mappingSize)
	if mappingOff < 0 || mappingSize < 0 || mappingOff+mappingSize > size {
		return xerrors.Errorf("invalid CID mapping descriptor: offset=%d size=%d sectorSize=%d", mappingOff, mappingSize, size)
	}
	blockLen := size - mappingOff
	indexLog.Infof("blockLen: %v", blockLen)
	block := make([]byte, blockLen)
	n, err = reader.ReadAt(block, mappingOff)
	if err != nil && err != io.EOF {
		return xerrors.Errorf("reading mapping+index block at offset %d: %w", mappingOff, err)
	}
	if int64(n) < blockLen {
		return xerrors.Errorf("short read for mapping+index block: got %d want %d", n, blockLen)
	}
	return id.UnmarshalBinary(block)
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

// Search finds the index of a segment by its Piece CID v1 (CommDS).
// Returns -1 if not found.
// For lookup by Piece CID v2 use SearchByPieceCIDV2.
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

// SearchByPieceCIDV2 finds the index of a segment by its Piece CID v2 (FRC-0069).
// Returns -1 if not found. Per FRC-1216, retrieval is supported by both CommDS and Piece CID v2.
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

// CIDMappingMagic is the 8-byte magic for the CID mapping section (layout matches exa-gateway sector.go).
const CIDMappingMagic = "CIDMAP01"

// buildCIDMappingSection builds the CID mapping section bytes from CidMappings.
// Layout: [magic 8 bytes] [section_total_size uint64] [entry1][entry2]...
// Each entry: [entry_size uint32] [segment_index as uint64 LE, 8 zero bytes] [cid_len uint16] [cid_bytes]
// section_total_size includes magic + size field + all entries.
// The mapping section is always written: at minimum magic + size (16 bytes) even when there are zero mappings.
func (id *IndexDataV2) buildCIDMappingSection() []byte {
	const sizeField = 8
	headerSize := len(CIDMappingMagic) + sizeField // 16
	var entries []byte
	n := len(id.Entries)
	if n > len(id.CidMappings) {
		n = len(id.CidMappings)
	}
	for i := 0; i < n; i++ {
		c := id.CidMappings[i]
		if c == nil || !c.Defined() {
			continue
		}
		cidBytes := c.Bytes()
		// entry_size (4) + piece_id placeholder 16 (segment index 8 + 8 zero) + cid_len (2) + cid_bytes
		entrySize := 4 + 16 + 2 + len(cidBytes)
		entry := make([]byte, entrySize)
		binary.LittleEndian.PutUint32(entry[0:4], uint32(entrySize))
		binary.LittleEndian.PutUint64(entry[4:12], uint64(i))
		// 12:16 zero
		binary.LittleEndian.PutUint16(entry[20:22], uint16(len(cidBytes)))
		copy(entry[22:], cidBytes)
		entries = append(entries, entry...)
	}
	totalSize := headerSize + len(entries)
	if totalSize < headerSize {
		totalSize = headerSize
	}
	out := make([]byte, 0, totalSize)
	out = append(out, CIDMappingMagic...)
	buf8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf8, uint64(totalSize))
	out = append(out, buf8...)
	out = append(out, entries...)
	return out
}

// MarshalBinary produces the combined layout: [CID mapping section][index section].
// The mapping section is always written (at least magic + size; see buildCIDMappingSection).
// It builds the mapping section, inserts a special SegmentDesc (MulticodecCIDMappingSection) into the index entries with Offset = id.Offset and Size = mapping section length,
// then serializes the index section. The returned binary is intended to be written at sector offset id.Offset (mapping then index follow).
func (id *IndexDataV2) MarshalBinary() (data []byte, err error) {
	mappingSection := id.buildCIDMappingSection() // always at least magic+size (16 bytes)
	mappingSize := uint64(len(mappingSection))
	mappingOffset := uint64(id.Offset)

	// Build index entries: original Entries + special entry for CID mapping section
	entriesCnt := len(id.Entries)
	indexSection := make([]byte, EntrySize*(entriesCnt+1))
	for i, r := range id.Entries {
		if r != nil {
			r.SerializeFr32Into(indexSection[i*EntrySize : (i+1)*EntrySize])
		}
	}

	var zeroComm merkletree.Node
	NewDataSegmentIndexEntry((*fr32.Fr32)(&zeroComm), mappingOffset, mappingSize).
		WithCodec(MulticodecCIDMappingSection, merkletree.Node{}).
		WithUpdatedChecksum().
		SerializeFr32Into(indexSection[entriesCnt*EntrySize : (entriesCnt+1)*EntrySize])

	return append(mappingSection, indexSection...), nil
}

// parseCIDMappingSection parses the CID mapping section body (after magic+size) and returns (segmentIndex, cid) pairs.
// Entry format: [entry_size uint32][segment_index uint64][8 zero][cid_len uint16][cid_bytes]
func parseCIDMappingSection(body []byte) ([]struct {
	segmentIndex uint64
	cid          cid.Cid
}, error) {
	const minEntrySize = 4 + 16 + 2 // entry_size + segment_id placeholder + cid_len
	var out []struct {
		segmentIndex uint64
		cid          cid.Cid
	}
	pos := 0
	for pos+4 <= len(body) {
		entrySize := binary.LittleEndian.Uint32(body[pos:])
		pos += 4
		payloadLen := int(entrySize) - 4
		if payloadLen < minEntrySize-4 || pos+payloadLen > len(body) {
			break
		}
		segmentIndex := binary.LittleEndian.Uint64(body[pos:])
		cidLen := binary.LittleEndian.Uint16(body[pos+16:])
		cidEnd := pos + 18 + int(cidLen)
		if cidEnd > pos+payloadLen {
			break
		}
		c, err := cid.Cast(body[pos+18 : cidEnd])
		if err != nil {
			break
		}
		out = append(out, struct {
			segmentIndex uint64
			cid          cid.Cid
		}{segmentIndex, c})
		pos += payloadLen
	}
	return out, nil
}

// UnmarshalBinary expects the combined layout from MarshalBinary: [CID mapping section][index section].
// The mapping section must be present (data must start with CIDMappingMagic). It is always parsed; then the index section is parsed into Entries.
// Index-only data is not supported; if the magic is missing, UnmarshalBinary returns an error.
func (id *IndexDataV2) UnmarshalBinary(data []byte) error {
	if len(data) < len(CIDMappingMagic)+8 {
		return xerrors.Errorf("data too short for CID mapping section (need at least magic+size)")
	}
	if string(data[:len(CIDMappingMagic)]) != CIDMappingMagic {
		return xerrors.Errorf("data does not start with CID mapping magic; combined [mapping][index] layout required")
	}
	mappingSectionSize := binary.LittleEndian.Uint64(data[len(CIDMappingMagic) : len(CIDMappingMagic)+8])
	indexLog.Infof("Unmarshaling index data. mapping section size: %v", mappingSectionSize)
	const headerSize = len(CIDMappingMagic) + 8
	if mappingSectionSize < uint64(headerSize) || int(mappingSectionSize) > len(data) {
		return xerrors.Errorf("invalid CID mapping section size %d", mappingSectionSize)
	}
	body := data[headerSize:mappingSectionSize]
	mappingPairs, err := parseCIDMappingSection(body)
	indexLog.Infof("unmarshaling index data. mappingPairs count: %v", len(mappingPairs))
	if err != nil {
		return xerrors.Errorf("parse CID mapping section: %w", err)
	}
	indexData := data[mappingSectionSize:]
	if rem := len(indexData) % EntrySize; rem != 0 {
		return xerrors.Errorf("index data is not a multiple of EntrySize: %d %% %d != 0 (%d)",
			len(indexData), EntrySize, rem)
	}

	*id = IndexDataV2{}
	numEntries := len(indexData) / EntrySize
	indexLog.Infof("unmarshaling index data. index section size: %v, entries: %v", len(indexData), numEntries)
	id.Entries = make([]*SegmentDesc, numEntries)
	for i := 0; i < numEntries; i++ {
		var entry SegmentDesc
		err := entry.UnmarshalBinary(indexData[i*EntrySize : (i+1)*EntrySize])
		if err != nil {
			return xerrors.Errorf("unmarshaling entry at index %d: %w", i, err)
		}
		if err := entry.Validate(); err != nil {
			return xerrors.Errorf("entry at index %v is invalid: %v", i, err)
		}
		id.Entries[i] = &entry
	}
	// Restore CidMappings: length = blob count (last entry is special CID mapping descriptor)
	blobCount := numEntries
	if numEntries > 0 && id.Entries[numEntries-1] != nil && id.Entries[numEntries-1].Multicodec == MulticodecCIDMappingSection {
		blobCount = numEntries - 1
	}
	id.CidMappings = make([]*cid.Cid, blobCount)
	for _, p := range mappingPairs {
		if p.segmentIndex >= uint64(blobCount) {
			continue
		}
		cCopy := p.cid
		id.CidMappings[p.segmentIndex] = &cCopy
	}
	return nil
}
