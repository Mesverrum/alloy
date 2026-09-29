package snmp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadFingerprintLibrary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fingerprinters.yml")
	require.NoError(t, os.WriteFile(path, []byte(`
fingerprinters:
  network:
    matchers:
      - label: sysObjectID
        regex: ^\.?1\.3\.6\.1\.4\.1\.8072\.3\.2\.10\.barracuda$
        modules_hot: [if_mib]
        modules_cold: [if_mib_meta, ip_addr, ucd_mib, barracuda_email_gateway]
        modules_topology: []
        comment: barracuda_email_gateway 1.3.6.1.4.1.8072.3.2.10.barracuda
      - label: sysObjectID
        regex: ^\.?1\.3\.6\.1\.4\.1\.9\.1\.1$
        modules_hot: [if_mib]
        modules_cold: [if_mib_meta]
        modules_topology: [lldp_mib]
        comment: cisco_switch 1.3.6.1.4.1.9.1.1
      - label: sysObjectID
        regex: ^\.?1\.3\.6\.1\.4\.1\.9\.1\.2$
        modules_hot: [if_mib]
        modules_cold: [if_mib_meta]
        modules_topology: [lldp_mib]
        comment: cisco_switch 1.3.6.1.4.1.9.1.2
`), 0o644))

	lib, err := loadFingerprintLibrary(path, "network")
	require.NoError(t, err)
	require.Len(t, lib.LibraryHash, 16)
	require.Equal(t, "network", lib.Fingerprinter)
	require.Len(t, lib.Profiles, 2)
	require.Equal(t, "barracuda_email_gateway", lib.Profiles[0].Name)
	require.Equal(t, []string{"if_mib"}, lib.Profiles[0].Hot)
	require.Contains(t, lib.Profiles[0].Cold, "barracuda_email_gateway")
	require.Empty(t, lib.Profiles[0].Topology)
	require.Equal(t, "cisco_switch", lib.Profiles[1].Name)

	var state libraryState
	state.set(lib)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/fingerprints", nil)
	state.serveHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var got FingerprintLibrary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, lib.LibraryHash, got.LibraryHash)
	require.Len(t, got.Profiles, 2)
}

func TestLoadFingerprintLibraryMissing(t *testing.T) {
	_, err := loadFingerprintLibrary(filepath.Join(t.TempDir(), "missing.yml"), "network")
	require.Error(t, err)
}
