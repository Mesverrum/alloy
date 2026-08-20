package devicejoin

import (
	"testing"

	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/stretchr/testify/require"
)

func TestLookupPrimaryAndAlias(t *testing.T) {
	idx := NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":      "10.0.0.2",
			"device_name":  "spine1",
			"snmp_group":   "hq",
			"snmp_aliases": "10.0.0.10,192.168.1.1",
		}),
	})
	require.Equal(t, 3, idx.Len())

	id, ok := idx.Lookup("10.0.0.10")
	require.True(t, ok)
	require.Equal(t, "spine1", id.DeviceName)
	require.Equal(t, "10.0.0.2", id.Address)
	require.Equal(t, "hq", id.Group)

	id, ok = idx.Lookup("8.8.8.8", "192.168.1.1")
	require.True(t, ok)
	require.Equal(t, "spine1", id.DeviceName)

	_, ok = idx.Lookup("1.2.3.4")
	require.False(t, ok)

	id, ok = idx.Lookup("8.8.8.8", "spine1")
	require.True(t, ok)
	require.Equal(t, "spine1", id.DeviceName)

	id, ok = idx.Lookup("::ffff:10.0.0.2")
	require.True(t, ok)
	require.Equal(t, "spine1", id.DeviceName)
}

func TestLookupYamlAliasesKey(t *testing.T) {
	idx := NewIndex([]discovery.Target{
		discovery.NewTargetFromMap(map[string]string{
			"address":     "10.0.0.9",
			"device_name": "client1",
			"aliases":     "172.17.0.1",
		}),
	})
	id, ok := idx.Lookup("172.17.0.1")
	require.True(t, ok)
	require.Equal(t, "client1", id.DeviceName)
}

func TestEmptyIndex(t *testing.T) {
	var idx *Index
	_, ok := idx.Lookup("10.0.0.1")
	require.False(t, ok)
	require.Equal(t, 0, NewIndex(nil).Len())
}
