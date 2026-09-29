package snmp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// FingerprintProfile is one named profile from fingerprinters.yml (comment first token).
type FingerprintProfile struct {
	Name     string   `json:"name"`
	Hot      []string `json:"hot"`
	Cold     []string `json:"cold"`
	Topology []string `json:"topology"`
}

// FingerprintLibrary is the catalog a collector exposes for the devices UI.
type FingerprintLibrary struct {
	Fingerprinter string               `json:"fingerprinter"`
	LibraryHash   string               `json:"library_hash"`
	Source        string               `json:"source"`
	Profiles      []FingerprintProfile `json:"profiles"`
}

type fingerprintersFile struct {
	Fingerprinters map[string]struct {
		Matchers []struct {
			ModulesHot      []string `yaml:"modules_hot"`
			ModulesCold     []string `yaml:"modules_cold"`
			ModulesTopology []string `yaml:"modules_topology"`
			Comment         string   `yaml:"comment"`
		} `yaml:"matchers"`
	} `yaml:"fingerprinters"`
}

func loadFingerprintLibrary(path, fingerprinter string) (FingerprintLibrary, error) {
	out := FingerprintLibrary{
		Fingerprinter: fingerprinter,
		Source:        path,
		Profiles:      []FingerprintProfile{},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	sum := sha256.Sum256(raw)
	out.LibraryHash = hex.EncodeToString(sum[:8])

	var doc fingerprintersFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return out, err
	}
	fp, ok := doc.Fingerprinters[fingerprinter]
	if !ok {
		return out, fmt.Errorf("fingerprinter %q not in %s", fingerprinter, path)
	}

	byName := map[string]FingerprintProfile{}
	for _, m := range fp.Matchers {
		name := strings.Fields(strings.TrimSpace(m.Comment))
		if len(name) == 0 || name[0] == "" || !isIdentStart(name[0][0]) {
			continue
		}
		hot := append([]string{}, m.ModulesHot...)
		cold := append([]string{}, m.ModulesCold...)
		topo := append([]string{}, m.ModulesTopology...)
		if len(hot)+len(cold)+len(topo) == 0 {
			continue
		}
		entry := FingerprintProfile{Name: name[0], Hot: hot, Cold: cold, Topology: topo}
		if prev, exists := byName[entry.Name]; exists {
			if len(hot)+len(cold)+len(topo) > len(prev.Hot)+len(prev.Cold)+len(prev.Topology) {
				byName[entry.Name] = entry
			}
			continue
		}
		byName[entry.Name] = entry
	}
	out.Profiles = make([]FingerprintProfile, 0, len(byName))
	for _, p := range byName {
		out.Profiles = append(out.Profiles, p)
	}
	sort.Slice(out.Profiles, func(i, j int) bool { return out.Profiles[i].Name < out.Profiles[j].Name })
	return out, nil
}

func isIdentStart(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

type libraryState struct {
	mu  sync.RWMutex
	lib FingerprintLibrary
}

func (s *libraryState) set(lib FingerprintLibrary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lib = lib
}

func (s *libraryState) get() FingerprintLibrary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lib
}

func (s *libraryState) serveHTTP(w http.ResponseWriter, _ *http.Request) {
	lib := s.get()
	if lib.LibraryHash == "" {
		http.Error(w, "fingerprint library not loaded", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(lib)
}
