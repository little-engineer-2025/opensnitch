package nftables

import (
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
)

func TestGetChainKey(t *testing.T) {
	assert.Equal(t, "", getChainKey("name", nil))
	assert.Equal(t, "name-INPUT-1", getChainKey("name", &nftables.Table{
		Name:   "INPUT",
		Family: nftables.TableFamilyINet,
	}))
}
