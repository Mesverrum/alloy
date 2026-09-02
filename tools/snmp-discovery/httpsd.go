package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type catalogEntry struct {
	Target   AlloyTarget `json:"target"`
	LastSeen time.Time   `json:"last_seen"`
	Misses   int         `json:"misses"`
}

type catalog struct {
	mu      sync.RWMutex
	entries []catalogEntry
	updated time.Time
}

func newCatalog() *catalog {
	return &catalog{entries: []catalogEntry{}}
}

func (c *catalog) replace(targets []AlloyTarget) {
	now := time.Now().UTC()
	if targets == nil {
		targets = []AlloyTarget{}
	}
	entries := make([]catalogEntry, 0, len(targets))
	for _, t := range targets {
		entries = append(entries, catalogEntry{Target: t, LastSeen: now, Misses: 0})
	}
	c.mu.Lock()
	c.entries = entries
	c.updated = now
	c.mu.Unlock()
}

func (c *catalog) loadEntries(entries []catalogEntry) {
	if entries == nil {
		entries = []catalogEntry{}
	}
	c.mu.Lock()
	c.entries = append([]catalogEntry(nil), entries...)
	c.updated = time.Now().UTC()
	c.mu.Unlock()
}

func (c *catalog) snapshot() ([]AlloyTarget, time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]AlloyTarget, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e.Target)
	}
	return out, c.updated
}

func (c *catalog) snapshotEntries() []catalogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]catalogEntry(nil), c.entries...)
}

func (c *catalog) dropAddresses(addrs []string) int {
	if len(addrs) == 0 {
		return 0
	}
	drop := map[string]struct{}{}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a != "" {
			drop[a] = struct{}{}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := make([]catalogEntry, 0, len(c.entries))
	n := 0
	for _, e := range c.entries {
		if _, ok := drop[e.Target.Address]; ok {
			n++
			continue
		}
		kept = append(kept, e)
	}
	c.entries = kept
	return n
}

// mergeFound is ktranslate-style housekeeping: found resets the miss counter;
// unseen targets increment Misses and drop once Misses >= maxMisses.
// maxMisses <= 0 means never purge (LibreNMS-sticky).
func (c *catalog) mergeFound(found []AlloyTarget, now time.Time, maxMisses int) []AlloyTarget {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	byAddr := map[string]catalogEntry{}
	for _, e := range c.entries {
		byAddr[e.Target.Address] = e
	}
	seen := map[string]struct{}{}
	for _, t := range found {
		seen[t.Address] = struct{}{}
		byAddr[t.Address] = catalogEntry{Target: t, LastSeen: now, Misses: 0}
	}
	keep := make([]catalogEntry, 0, len(byAddr))
	out := make([]AlloyTarget, 0, len(byAddr))
	for addr, e := range byAddr {
		if _, ok := seen[addr]; !ok {
			e.Misses++
			if maxMisses > 0 && e.Misses >= maxMisses {
				continue
			}
			byAddr[addr] = e
		}
		keep = append(keep, byAddr[addr])
		out = append(out, byAddr[addr].Target)
	}
	c.entries = keep
	c.updated = now
	return out
}

type catalogStateFile struct {
	Updated time.Time      `json:"updated"`
	Entries []catalogEntry `json:"entries"`
}

func writeCatalogState(path string, c *catalog) error {
	if path == "" {
		return nil
	}
	c.mu.RLock()
	st := catalogStateFile{Updated: c.updated, Entries: append([]catalogEntry(nil), c.entries...)}
	c.mu.RUnlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeFileAtomic(path, b, 0o644)
}

func readCatalogState(path string) ([]catalogEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st catalogStateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return st.Entries, nil
}

func applyShardQuery(r *http.Request, targets []AlloyTarget) ([]AlloyTarget, error) {
	shard, shards, filter, err := parseShardQuery(r.URL.Query().Get("shard"), r.URL.Query().Get("shards"))
	if err != nil {
		return nil, err
	}
	if !filter {
		return targets, nil
	}
	return filterShard(targets, shard, shards), nil
}

func httpSDHandler(c *catalog, prometheusParams bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		targets, updated := c.snapshot()
		targets, err := applyShardQuery(r, targets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, err := json.MarshalIndent(httpSDGroups(targets, prometheusParams), "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		body = append(body, '\n')
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Snmp-Discovery-Count", strconv.Itoa(len(targets)))
		if !updated.IsZero() {
			w.Header().Set("Last-Modified", updated.Format(http.TimeFormat))
		}
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func alloyYAMLHandler(c *catalog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		targets, _ := c.snapshot()
		targets, err := applyShardQuery(r, targets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if targets == nil {
			targets = []AlloyTarget{}
		}
		body, err := yaml.Marshal(targets)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("X-Snmp-Discovery-Count", strconv.Itoa(len(targets)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
	}
}

func healthzHandler(c *catalog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targets, updated := c.snapshot()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		ts := "never"
		if !updated.IsZero() {
			ts = updated.Format(time.RFC3339)
		}
		_, _ = w.Write([]byte("ok " + strconv.Itoa(len(targets)) + " targets " + ts + "\n"))
	}
}

func newDiscoveryMux(c *catalog) *http.ServeMux {
	mux := http.NewServeMux()
	// Alloy discovery.http + prometheus.exporter.snmp: labels name/module/auth.
	mux.HandleFunc("/sd", httpSDHandler(c, false))
	// Classic Prometheus → snmp_exporter: __param_module / __param_auth.
	mux.HandleFunc("/sd/prometheus", httpSDHandler(c, true))
	mux.HandleFunc("/alloy", alloyYAMLHandler(c))
	mux.HandleFunc("/healthz", healthzHandler(c))
	return mux
}
