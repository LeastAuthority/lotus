//+build gofuzz

package types

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	fleece "github.com/filecoin-project/lotus/fleece/fuzzing"
)

var crashLimit int

func init() {
	flag.IntVar(&crashLimit, "crash-limit", 1000, "number of crashing inputs to test before stopping")
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestFuzzBlockMsg(t *testing.T) {
	_, panics, _ := fleece.
		MustNewCrasherIterator(FuzzBlockMsg).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}

func TestFuzzBlockMsgStructural(t *testing.T) {
	_, panics, _ := fleece.
		MustNewCrasherIterator(FuzzBlockMsgStructural).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}