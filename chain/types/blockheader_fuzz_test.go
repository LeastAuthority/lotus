//+build gofuzz

package types

import (
	"testing"

	fleece "github.com/leastauthority/fleece/fuzzing"
	"github.com/stretchr/testify/require"
)

func TestFuzzBlockHeader(t *testing.T) {
	_, panics, _ := fleece.
		MustNewCrasherIterator(env, FuzzBlockHeader, filters...).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}

func TestFuzzBlockHeaderStructural(t *testing.T) {
	_, panics, _ := fleece.
		MustNewCrasherIterator(env, FuzzBlockHeaderStructural, filters...).
		TestFailingLimit(t, crashLimit)

	require.Zero(t, panics)
}
