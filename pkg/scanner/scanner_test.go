package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatByteSize(t *testing.T) {
	tests := []struct {
		size int64
		want string
	}{
		{0, "0.00B"},
		{1, "1.00B"},
		{1023, "1023.00B"},
		{1024, "1.00KB"},
		{1536, "1.50KB"},
		{1024 * 1024, "1.00MB"},
	}

	for _, tc := range tests {
		got := formatByteSize(tc.size)
		assert.Equal(t, got, tc.want)
	}
}
