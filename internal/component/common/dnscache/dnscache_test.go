package dnscache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeRes struct {
	calls int
	names map[string][]string
}

func (f *fakeRes) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.calls++
	if n, ok := f.names[addr]; ok {
		return n, nil
	}
	return nil, errors.New("nxdomain")
}

func TestLookupCachesHitAndMiss(t *testing.T) {
	res := &fakeRes{names: map[string][]string{
		"8.8.8.8": {"dns.google."},
	}}
	c := NewWithResolver(8, res, time.Second)
	require.NotNil(t, c)

	require.Equal(t, "dns.google", c.Lookup("8.8.8.8"))
	require.Equal(t, "dns.google", c.Lookup("8.8.8.8"))
	require.Equal(t, "", c.Lookup("1.2.3.4"))
	require.Equal(t, "", c.Lookup("1.2.3.4"))
	require.Equal(t, 2, res.calls)
}

func TestLookupUnmapsV4Mapped(t *testing.T) {
	res := &fakeRes{names: map[string][]string{
		"172.17.0.1": {"client1.lab"},
	}}
	c := NewWithResolver(8, res, time.Second)
	require.Equal(t, "client1.lab", c.Lookup("::ffff:172.17.0.1"))
	require.Equal(t, 1, res.calls)
}

func TestNewDisabled(t *testing.T) {
	require.Nil(t, New(0))
	require.Equal(t, "", (*Cache)(nil).Lookup("8.8.8.8"))
}
