// Package dnscache is an LRU reverse-DNS cache matching loki.source.syslog's
// UDP host cache (hashicorp/golang-lru + net.LookupAddr).
//
// Syslog looks up one UDP source per datagram with no timeout. Flow records
// look up two conversation IPs per record, so lookups use a short timeout and
// cache negative answers (empty string) to avoid retrying NXDOMAIN on the hot path.
package dnscache

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// DefaultSize matches loki.source.syslog udp_host_cache_size.
const DefaultSize = 128

// DefaultTimeout caps a miss. ktranslate used 80ms for the same reason.
const DefaultTimeout = 80 * time.Millisecond

// Resolver is the subset of net.Resolver used for reverse lookups.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Cache maps IP → PTR hostname. A nil Cache is a no-op.
type Cache struct {
	lru     *lru.Cache[string, string]
	res     Resolver
	timeout time.Duration
}

// New returns an LRU cache of the given size. size <= 0 disables (returns nil).
func New(size int) *Cache {
	return NewWithResolver(size, net.DefaultResolver, DefaultTimeout)
}

// NewWithResolver is for tests.
func NewWithResolver(size int, res Resolver, timeout time.Duration) *Cache {
	if size <= 0 || res == nil {
		return nil
	}
	c, err := lru.New[string, string](size)
	if err != nil {
		return nil
	}
	return &Cache{lru: c, res: res, timeout: timeout}
}

// Lookup returns the first PTR name (lowercased, trailing dot stripped), or "".
func (c *Cache) Lookup(addr string) string {
	if c == nil || c.lru == nil {
		return ""
	}
	key := canon(addr)
	if key == "" {
		return ""
	}
	if v, ok := c.lru.Get(key); ok {
		return v
	}
	ctx := context.Background()
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	host := ""
	if names, err := c.res.LookupAddr(ctx, key); err == nil && len(names) > 0 {
		host = strings.ToLower(strings.TrimSuffix(names[0], "."))
	}
	c.lru.Add(key, host)
	return host
}

func canon(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, ok := strings.Cut(raw, "%"); ok {
		raw = host
	}
	addr, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return raw
	}
	return addr.Unmap().String()
}
