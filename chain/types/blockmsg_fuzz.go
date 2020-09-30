//+build gofuzz

package types

import (
	"bytes"
	"fmt"

	"github.com/google/go-cmp/cmp"
	gfuzz "github.com/google/gofuzz"
	fleece "github.com/leastauthority/fleece/fuzzing"
)

// Fuzzes DecodeBlockMsg using random data
func FuzzBlockMsg(data []byte) int {
	msg, err := DecodeBlockMsg(data)
	if err != nil {
		return fleece.FuzzNormal
	}
	encodedMsg, err := msg.Serialize()
	if err != nil {
		panic(fmt.Sprintf("Error in serializing BlockMsg: %v", err))
	}

	msg2, err := DecodeBlockMsg(encodedMsg)
	if err != nil {
		panic(fmt.Errorf("second decode errored: %w", err))
	}
	encodedMsg2, err := msg2.Serialize()
	if err != nil {
		panic(fmt.Errorf("second encode errored: %w", err))
	}

	if !bytes.Equal(encodedMsg, encodedMsg2) {
		panic(fmt.Sprintf("Fuzz data and serialized data are not equal: %v", err))
	}
	return fleece.FuzzInteresting
}

// Structural fuzzing on the BlockMsg struct to provide valid binary data.
func FuzzBlockMsgStructural(data []byte) int {
	blockmsg := BlockMsg{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&blockmsg)
	encodedMsg, err := blockmsg.Serialize()
	if err != nil {
		panic(fmt.Errorf("unable to serialize BlockMsg: %w", err))
	}
	msg, err := DecodeBlockMsg(encodedMsg)
	if err != nil {
		panic(fmt.Errorf("unable to decode BlockMsg: %w", err))
	}

	// Checks if the decoded message is different to the initial blockmsg.
	if !cmp.Equal(blockmsg, msg) {
		panic(fmt.Sprintf("Decoded BlockMsg and serialized BlockMsg are not equal: %v", err))
	}
	return fleece.FuzzDiscard
}
