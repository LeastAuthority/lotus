//+build gofuzz

package types

import (
	"bytes"
	"fmt"

	"github.com/google/go-cmp/cmp"
	gfuzz "github.com/google/gofuzz"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzBlockHeader(data []byte) int {
	header1, err := DecodeBlock(data)
	if err != nil {
		return fleece.FuzzNormal
	}
	header1Bytes, err := header1.Serialize()
	if err != nil {
		panic(fmt.Sprintf("Error in serializing BlockHeader: %v", err))
	}

	header2, err := DecodeBlock(header1Bytes)
	if err != nil {
		panic(fmt.Errorf("second decode errored: %w", err))
	}
	header2Bytes, err := header2.Serialize()
	if err != nil {
		panic(fmt.Errorf("second encode errored: %w", err))
	}

	if !bytes.Equal(header1Bytes, header2Bytes) {
		panic(fmt.Sprintf("Fuzz data and serialized data are not equal: %v", err))
	}

	if !cmp.Equal(header1, header2) {
		panic(fmt.Sprintf("deserialized messages are not equal: %v", err))
	}
	return fleece.FuzzInteresting
}

func FuzzBlockHeaderStructural(data []byte) int {
	blockHeader := BlockHeader{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&blockHeader)
	header1Bytes, err := blockHeader.Serialize()
	if err != nil {
		return fleece.FuzzNormal
	}

	header1, err := DecodeBlockHeader(header1Bytes)
	if err != nil {
		panic(fmt.Errorf("unable to decode BlockHeader: %w", err))
	}

	header2Bytes, err := header1.Serialize()
	if err != nil {
		panic(fmt.Errorf("unable to serialize: %w", err))
	}

	header2, err := DecodeBlockHeader(header2Bytes)
	if err != nil {
		panic(fmt.Errorf("unable to deserialize BlockHeader: %w", err))
	}

	if !bytes.Equal(header1Bytes, header2Bytes) {
		panic(fmt.Sprintf("serialized messages are not equal: %v", err))
	}

	if !cmp.Equal(header1, header2) {
		panic(fmt.Sprintf("deserialized messages are not equal: %v", err))
	}
	return fleece.FuzzDiscard
}
