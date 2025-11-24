package index

import (
	"fmt"
	"github.com/filecoin-project/go-data-segment/fr32"
	"github.com/filecoin-project/go-state-types/abi"
	"golang.org/x/xerrors"
	"io"
	"runtime"
	"sync"
)

// DataSegmentIndexStartOffset takes in the padded size of the deal and returns the starting offset
// of data segment index in unpadded units.
func DataSegmentIndexStartOffset(dealSize abi.PaddedPieceSize) uint64 {
	mie := MaxIndexEntriesInDeal(dealSize)
	fromBack := uint64(mie) * uint64(EntrySizeV2)
	fromBack = fromBack - fromBack/128 // safe because EntrySize = 128 (which is a multiple of 128) and min(MaxIndexEntriesInDeal(x)) = 4
	return uint64(dealSize.Unpadded()) - fromBack
}

// ParseDataSegmentIndex takes in a reader of of unppaded deal data, it should start at offset
// returned by DataSegmentIndexStartOffset
// After parsing use IndexData#validPos() to gather validPos data segments
func ParseDataSegmentIndex(unpaddedReader io.Reader) (IndexData, error) {
	const (
		unpaddedChunk = 127
		paddedChunk   = 128
	)

	// Read all unpadded data (up to 32 MiB Max as per FRC for 64 GiB sector)
	unpaddedData, err := io.ReadAll(unpaddedReader)
	if err != nil {
		return IndexData{}, xerrors.Errorf("reading unpadded data: %w", err)
	}

	// Make sure it's aligned to 127
	if len(unpaddedData)%unpaddedChunk != 0 {
		return IndexData{}, fmt.Errorf("unpadded data length %d is not a multiple of 127", len(unpaddedData))
	}
	numChunks := len(unpaddedData) / unpaddedChunk

	// Prepare padded output buffer
	paddedData := make([]byte, numChunks*paddedChunk)

	// Parallel pad
	var wg sync.WaitGroup
	concurrency := runtime.NumCPU()
	chunkPerWorker := (numChunks + concurrency - 1) / concurrency

	for w := 0; w < concurrency; w++ {
		start := w * chunkPerWorker
		end := (w + 1) * chunkPerWorker
		if end > numChunks {
			end = numChunks
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				in := unpaddedData[i*unpaddedChunk : (i+1)*unpaddedChunk]
				out := paddedData[i*paddedChunk : (i+1)*paddedChunk]
				fr32.Pad(in, out)
			}
		}(start, end)
	}
	wg.Wait()

	// Decode entries
	// MarshalBinary() returns EntrySize (128 bytes) per entry
	// IndexReader() unpads the entire block: 128 bytes -> 127 bytes per entry (after Fr32 unpadding)
	// So we need to pad back to 128 bytes per entry to unmarshal
	unpaddedEntrySize := (uint64(EntrySizeV2) / 128) * 127 // (128 / 128) * 127 = 1 * 127 = 127 bytes
	numEntries := uint64(len(unpaddedData)) / unpaddedEntrySize

	// Pre-allocate entries slice to hold all entries (including zero-filled ones)
	allEntries := make([]*SegmentDescV2, numEntries)
	validEntries := make([]bool, numEntries)
	validCnt := 0

	for i := uint64(0); i < numEntries; i++ {
		// Each entry in unpadded format is 127 bytes (1 * 127)
		// After Fr32 padding, it becomes 128 bytes (1 * 128) = EntrySize
		// The paddedData already contains the correctly padded entries
		entryStartPadded := i * EntrySizeV2 // Each entry is EntrySize (128) bytes after padding
		if entryStartPadded+EntrySizeV2 > uint64(len(paddedData)) {
			// Not enough padded data, leave as nil
			continue
		}

		entryData := paddedData[entryStartPadded : entryStartPadded+EntrySizeV2]
		var entry SegmentDescV2
		if err := entry.UnmarshalBinary(entryData); err != nil {
			continue
		}
		if entry.Validate() == nil {
			allEntries[i] = &entry
			validEntries[i] = true
			validCnt++
		}
	}
	if validCnt == 0 {
		// all entries are invalid, maybe it's v1
		return parseDataSegmentV1(unpaddedData, paddedData)
	}

	return IndexData{
		Entries:  allEntries,
		validPos: validEntries,
	}, nil
}

func parseDataSegmentV1(unpaddedData, paddedData []byte) (IndexData, error) {
	unpaddedEntrySize := (uint64(EntrySizeV1) / 128) * 127 // (128 / 128) * 127 = 1 * 127 = 127 bytes
	numEntries := uint64(len(unpaddedData)) / unpaddedEntrySize

	// Pre-allocate entries slice to hold all entries (including zero-filled ones)
	allEntries := make([]*SegmentDescV2, numEntries)
	validEntries := make([]bool, numEntries)

	emptyEntry := &SegmentDescV1{}
	for i := uint64(0); i < numEntries; i++ {
		entryStartPadded := i * EntrySizeV1
		if entryStartPadded+EntrySizeV2 > uint64(len(paddedData)) {
			// Not enough padded data, leave as nil
			continue
		}

		entryData := paddedData[entryStartPadded : entryStartPadded+EntrySizeV1]

		if err := emptyEntry.UnmarshalBinary(entryData); err != nil {
			continue
		}
		v2Entry := emptyEntry.ToV2()
		if v2Entry.Validate() == nil {
			allEntries[i] = &v2Entry
			validEntries[i] = true
		}
	}

	return IndexData{
		Entries:  allEntries,
		validPos: validEntries,
	}, nil
}
