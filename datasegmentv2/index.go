package datasegmentv2

import (
	"bytes"
	"encoding"
	"io"
	"runtime"
	"sort"

	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-data-segment/util"
	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/filecoin-project/go-fil-commp-hashhash/commp2"
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

const readBlockSize = 4096

// blobTask is sent from the assembler to workers: one blob's data to compute digest.
type blobTask struct {
	index  int   // original blob index (for ordering results)
	offset int64 // sector offset of this blob
	size   int64
	data   []byte // copy of blob data
}

// blobResult is sent from workers back to the collector.
type blobResult struct {
	index   int
	segment *SegmentDesc
}

// BuildFromSector builds the index from sector data using a reader goroutine, an assembler goroutine, and multiple worker goroutines.
// One goroutine only reads the sector in 4KB blocks and sends them to a second goroutine, which assembles the stream,
// extracts blob data by offsets/sizes, and sends computation tasks to workers that run commp2 digest; results are collected and ordered.
func (id *IndexDataV2) BuildFromSector(sector io.ReaderAt, blobOffsets []int64, blobSizes []int64) error {
	if len(blobSizes) != len(blobOffsets) {
		return xerrors.Errorf("invalid blobs. offsets and sizes should be of the same length")
	}
	blobCnt := len(blobOffsets)
	if blobCnt == 0 {
		return xerrors.Errorf("empty blobs")
	}

	// Sort blob indices by offset so the assembler can emit in read order and compact the buffer.
	type blobInfo struct {
		index        int
		offset, size int64
	}
	blobs := make([]blobInfo, blobCnt)
	for i := range blobOffsets {
		blobs[i] = blobInfo{index: i, offset: blobOffsets[i], size: blobSizes[i]}
	}
	sort.Slice(blobs, func(i, j int) bool { return blobs[i].offset < blobs[j].offset })

	sectorEnd := int64(0)
	for _, b := range blobs {
		if end := b.offset + b.size; end > sectorEnd {
			sectorEnd = end
		}
	}

	numWorkers := min(runtime.NumCPU(), blobCnt)

	taskCh := make(chan blobTask, numWorkers*2)
	resultCh := make(chan blobResult, numWorkers*2)
	// blockCh carries 4KB (or smaller) chunks from reader to assembler; sender closes when done.
	blockCh := make(chan []byte, 32)

	// Worker goroutines: consume tasks, compute digest, send results.
	for w := 0; w < numWorkers; w++ {
		go func() {
			for t := range taskCh {
				cal := commp2.Calc{}
				if err := cal.BeginAt(uint64(t.offset)); err != nil {
					resultCh <- blobResult{index: t.index, segment: nil}
					continue
				}
				cal.Write(t.data)
				commP, _, _ := cal.Digest()
				resultCh <- blobResult{
					index:   t.index,
					segment: NewDataSegmentIndexEntry((*fr32.Fr32)(commP), uint64(t.offset), uint64(t.size)),
				}
			}
		}()
	}

	// Goroutine 1: only read sector in 4KB blocks and send to blockCh.
	go func() {
		for readPos := int64(0); readPos < sectorEnd; {
			toRead := readBlockSize
			if sectorEnd-readPos < int64(toRead) {
				toRead = int(sectorEnd - readPos)
			}
			readBlock := make([]byte, toRead)
			nr, err := sector.ReadAt(readBlock, readPos)
			if err != nil || nr == 0 {
				break
			}
			blockCh <- readBlock
			readPos += int64(nr)
		}
		close(blockCh)
	}()

	// Goroutine 2: receive blocks in order, assemble buffer, parse out blobs and send tasks to taskCh.
	go func() {
		defer close(taskCh)
		var buffer []byte
		var bufferBase int64
		readPos := int64(0)
		nextBlob := 0

		for chunk := range blockCh {
			buffer = append(buffer, chunk...)
			readPos += int64(len(chunk))

			// Discard prefix we no longer need: keep only [nextBlobStart, readPos] to bound memory.
			if nextBlob < blobCnt {
				wantBase := blobs[nextBlob].offset
				if wantBase > bufferBase {
					drop := wantBase - bufferBase
					if drop <= int64(len(buffer)) {
						buffer = buffer[drop:]
						bufferBase = wantBase
					}
				}
			}

			// Emit all blobs that are now fully in buffer.
			for nextBlob < blobCnt {
				b := blobs[nextBlob]
				blobEnd := b.offset + b.size
				if readPos < blobEnd {
					break
				}
				startInBuf := b.offset - bufferBase
				endInBuf := blobEnd - bufferBase
				if startInBuf < 0 || endInBuf > int64(len(buffer)) {
					break
				}
				data := make([]byte, b.size)
				copy(data, buffer[startInBuf:endInBuf])
				taskCh <- blobTask{index: b.index, offset: b.offset, size: b.size, data: data}
				nextBlob++

				oldBase := bufferBase
				if nextBlob < blobCnt {
					bufferBase = blobs[nextBlob].offset
				} else {
					bufferBase = readPos
				}
				drop := bufferBase - oldBase
				if drop > 0 && drop <= int64(len(buffer)) {
					buffer = buffer[drop:]
				}
			}
		}
	}()

	// Collect results: we receive blobCnt results (one per blob), order by index.
	segments := make([]*SegmentDesc, blobCnt)
	received := 0
	for received < blobCnt {
		r := <-resultCh
		if r.index >= 0 && r.index < blobCnt {
			segments[r.index] = r.segment
			received++
		}
	}

	// Verify we have all segments (workers send nil on BeginAt error).
	for i := range segments {
		if segments[i] == nil {
			return xerrors.Errorf("failed to build segment for blob %d (offset %d size %d)", i, blobOffsets[i], blobSizes[i])
		}
	}
	id.Entries = segments
	return nil
}

// ParseIndexSection reads the index section from the tail of the sector backwards.
// It reads 4KB chunks and within each chunk parses EntrySize-sized segment entries from the end
// backwards, validating each with checksum; when a checksum mismatch is found, the index section
// is considered ended and parsing stops.
// reader must allow reading the last size bytes (e.g. a SectionReader over the index region).
func (id *IndexDataV2) ParseIndexSection(reader io.ReaderAt, size int64) error {
	if size < int64(EntrySize) {
		return xerrors.Errorf("invalid index section: size %d < EntrySize %d", size, EntrySize)
	}

	const blockSize = 4096 // read 4KB at a time and scan backwards for entries
	entries := make([]*SegmentDesc, 0)
	buf := make([]byte, blockSize)
	// Read from the tail in 4KB chunks
	readEnd := size
	done := false

	for readEnd > 0 && !done {
		toRead := int64(blockSize)
		if readEnd < toRead {
			toRead = readEnd
		}
		// Align down to full entries so we never parse partial 128-byte blocks
		toRead = (toRead / int64(EntrySize)) * int64(EntrySize)
		if toRead == 0 {
			break
		}

		readStart := readEnd - toRead
		n, err := reader.ReadAt(buf[:toRead], readStart)
		if err != nil && err != io.EOF {
			return xerrors.Errorf("reading at offset %d: %w", readStart, err)
		}
		if n != int(toRead) {
			break
		}

		// Within this chunk, process 128-byte entries from the end backwards
		for i := int(toRead) - EntrySize; i >= 0; i -= EntrySize {
			var entry SegmentDesc
			if err := entry.UnmarshalBinary(buf[i : i+EntrySize]); err != nil {
				done = true
				break
			}
			if err := entry.Validate(); err != nil {
				// Checksum mismatch or other validation failure: index section has ended
				done = true
				break
			}
			entries = append(entries, &entry)
		}

		readEnd = readStart
	}

	// We collected from tail to head; reverse so entries are in logical order (first segment first)
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
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

var _ encoding.BinaryMarshaler = &IndexDataV2{}
var _ encoding.BinaryUnmarshaler = (*IndexDataV2)(nil)

func (id *IndexDataV2) MarshalBinary() (data []byte, err error) {
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
