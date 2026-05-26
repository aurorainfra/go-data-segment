package datasegmentv2

import (
	"bytes"
	"testing"

	"github.com/filecoin-project/go-data-segment/merkletree"
	"github.com/stretchr/testify/require"
)

func requireFr32ValidBytes(t *testing.T, data []byte) {
	t.Helper()
	require.Equal(t, 0, len(data)%merkletree.NodeSize)
	for off := 0; off < len(data); off += merkletree.NodeSize {
		require.Zero(t, data[off+merkletree.NodeSize-1]&0xc0, "node at offset %d is not Fr32-valid", off)
	}
}

func requireFr32ValidNodes(t *testing.T, nodes [NodesPerEntry]merkletree.Node) {
	t.Helper()
	for i, node := range nodes {
		require.Zero(t, node[merkletree.NodeSize-1]&0xc0, "node %d is not Fr32-valid", i)
	}
}

func TestSegmentDescRoundTripPreservesCommDataHighBits(t *testing.T) {
	digest := [32]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0xff,
	}
	entry := NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, digest[:], 123, 456).
		WithCodec(MulticodecCAR).
		WithUpdatedChecksum()

	serialized := entry.SerializeFr32()
	requireFr32ValidBytes(t, serialized)
	requireFr32ValidNodes(t, entry.IntoNodes())

	var decoded SegmentDesc
	require.NoError(t, decoded.UnmarshalBinary(serialized))
	require.NoError(t, decoded.Validate())
	require.Equal(t, entry.CommData, decoded.CommData)
	require.Equal(t, uint64(0xff), uint64(decoded.CommData[31]))
	require.Equal(t, entry.Multicodec, decoded.Multicodec)
	require.Equal(t, entry.Multihash, decoded.Multihash)
	require.Equal(t, entry.Offset, decoded.Offset)
	require.Equal(t, entry.Size, decoded.Size)
	require.Equal(t, entry.RawSize, decoded.RawSize)
	require.Equal(t, entry.Checksum, decoded.Checksum)
	require.True(t, bytes.Equal(serialized, decoded.SerializeFr32()))
}

func TestIndexMarshalBinaryIsFr32Valid(t *testing.T) {
	digest1 := [32]byte{31: 0xc0}
	digest2 := [32]byte{0xaa, 0xbb, 0xcc, 31: 0xff}
	entry1 := NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, digest1[:], 0, 256).WithUpdatedChecksum()
	entry2 := NewDataSegmentIndexEntryFromMultihash(MultihashBlake3, digest2[:], 1024, 512).
		WithCodec(MulticodecCAR).
		WithUpdatedChecksum()
	index := &IndexDataV2{
		Entries: []*SegmentDesc{entry1, entry2},
		Offset:  4096,
	}

	data, err := index.MarshalBinary()
	require.NoError(t, err)
	requireFr32ValidBytes(t, data)

	var decoded IndexDataV2
	require.NoError(t, decoded.UnmarshalBinary(data))
	require.Equal(t, int64(4096), decoded.Offset)
	require.Equal(t, 2, decoded.NumPieces())
	require.Equal(t, digest1, decoded.Entry(0).CommData)
	require.Equal(t, digest2, decoded.Entry(1).CommData)
}
