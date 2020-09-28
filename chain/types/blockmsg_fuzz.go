//+build gofuzz

package types

import (
	"bytes"
	"fmt"
	"github.com/google/go-cmp/cmp"

	gfuzz "github.com/google/gofuzz"
	fleece "github.com/filecoin-project/lotus/fleece/fuzzing"
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
	// Checks if the encoded message is different to the fuzz data.
	if !bytes.Equal(encodedMsg, data) {
		panic(fmt.Sprintf("Fuzz data and serialized data are not equal: %v", err))
	}
	return fleece.FuzzDiscard
}

// Structural fuzzing on the BlockMsg struct to provide valid binary data.
func FuzzBlockMsgStructural(data []byte) int {

	blockmsg := BlockMsg{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&blockmsg)
	encodedMsg, err := blockmsg.Serialize()
	if err != nil {
		return fleece.FuzzNormal
	}
	msg, err := DecodeBlockMsg(encodedMsg)
	if err != nil {
		panic(fmt.Sprintf("Error in decoding BlockMsg: %v", err))
	}

	// Checks if the decoded message is different to the initial blockmsg.
	if !cmp.Equal(blockmsg, msg) {
		panic(fmt.Sprintf("Decoded BlockMsg and serialized BlockMsg are not equal: %v", err))
	}
	return fleece.FuzzDiscard
}
