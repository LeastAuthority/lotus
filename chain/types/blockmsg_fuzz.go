//+build gofuzz

package types

import (
	"bytes"
	"fmt"

	"github.com/google/go-cmp/cmp"
	gfuzz "github.com/google/gofuzz"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

func FuzzBlockMsg(data []byte) int {
	msg1, err := DecodeBlockMsg(data)
	if err != nil {
		return fleece.FuzzNormal
	}
	msg1Bytes, err := msg1.Serialize()
	if err != nil {
		panic(fmt.Sprintf("Error in serializing BlockMsg: %v", err))
	}

	msg2, err := DecodeBlockMsg(msg1Bytes)
	if err != nil {
		panic(fmt.Errorf("second decode errored: %w", err))
	}
	msg2Bytes, err := msg2.Serialize()
	if err != nil {
		panic(fmt.Errorf("second encode errored: %w", err))
	}

	if !bytes.Equal(msg1Bytes, msg2Bytes) {
		panic(fmt.Sprintf("serialized messages are not equal: %v", err))
	}

	if !cmp.Equal(msg1, msg2) {
		panic(fmt.Sprintf("deserialized messages are not equal: %v", err))
	}
	return fleece.FuzzInteresting
}

func FuzzBlockMsgStructural(data []byte) int {
	blockMsg := BlockMsg{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&blockMsg)
	msg1Bytes, err := blockMsg.Serialize()
	if err != nil {
		return fleece.FuzzNormal
	}

	msg1, err := DecodeBlockMsg(msg1Bytes)
	if err != nil {
		panic(fmt.Errorf("unable to decode BlockMsg: %w", err))
	}

	msg2Bytes, err := msg1.Serialize()
	if err != nil {
		panic(fmt.Errorf("unable to serialize: %w", err))
	}

	msg2, err := DecodeBlockMsg(msg2Bytes)
	if err != nil {
		panic(fmt.Errorf("unable to deserialize BlockMsg: %w", err))
	}

	if !bytes.Equal(msg1Bytes, msg2Bytes) {
		panic(fmt.Sprintf("serialized messages are not equal: %v", err))
	}

	if !cmp.Equal(msg1, msg2) {
		panic(fmt.Sprintf("deserialized messages are not equal: %v", err))
	}
	return fleece.FuzzDiscard
}
