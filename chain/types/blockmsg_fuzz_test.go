//+build gofuzz

package types

import (
	"testing"

	fleece "github.com/leastauthority/fleece/fuzzing"
	"github.com/stretchr/testify/require"
)

func TestFuzzBlockMsg(t *testing.T) {
	_, panics, _ := fleece.
		MustNewCrasherIterator(env, FuzzBlockMsg, filters...).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}

func TestFuzzBlockMsgStructural(t *testing.T) {
	_, panics, _ := fleece.
		MustNewCrasherIterator(env, FuzzBlockMsgStructural, filters...).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}
