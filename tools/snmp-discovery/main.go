// Command snmp-discovery is a Prometheus-style SNMP service discovery helper.
//
// Admin object is a group file (CIDR + named auths), not a ktranslate devices.yaml.
// Secrets stay in snmp.yml. Community is never written to SD.
//
// This is a Discoverer, not an exporter. The exporter stays stock.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("snmp-discovery", flag.ContinueOnError)
	configPath := fs.String("config", "", "discovery groups YAML (CIDR-scoped named auths)")
	cidrs := fs.String("cidrs", "", "comma-separated CIDRs (legacy one-shot; prefer --config)")
	port := fs.Uint("port", 161, "default SNMP UDP port")
	snmpCfg := fs.String("snmp-config", "/etc/alloy/snmp-network.yml", "snmp_exporter snmp.yml (auths)")
	fpPath := fs.String("fingerprinters", "/etc/alloy/fingerprinters.yml", "fingerprint matchers (#1468)")
	fpName := fs.String("fingerprinter", "network", "default fingerprinters.<name>")
	authsFlag := fs.String("auths", "", "comma-separated auth names for --cidrs mode")
	outAlloy := fs.String("out-alloy", "/etc/alloy/snmp-targets.yml", "Alloy targets YAML")
	outSD := fs.String("out-file-sd", "/etc/alloy/snmp-file-sd.json", "Prometheus file_sd JSON")
	listen := fs.String("listen", "", "HTTP SD listen address (e.g. :9780). Serves /sd, /sd/prometheus, /alloy, /healthz")
	concurrency := fs.Int("concurrency", 8, "parallel SNMP probes")
	timeout := fs.Duration("timeout", 2*time.Second, "per-auth SNMP timeout")
	retries := fs.Int("retries", 0, "SNMP retries per auth")
	allowLarge := fs.Bool("allow-large", false, "allow CIDR sweeps wider than /22 (~1024 hosts)")
	interval := fs.Duration("interval", 0, "rescan period (0 = one-shot). Prefer 24h+ in production; reloads --config each pass.")
	overridesPath := fs.String("overrides", "", "optional overrides YAML (merged on top of --config)")
	ping := fs.Bool("ping", true, "ICMP-filter CIDR sweeps before SNMP (disable if mgmt drops ping)")
	pingTimeout := fs.Duration("ping-timeout", 400*time.Millisecond, "ICMP wait after last echo")
	misses := fs.Int("misses", 3, "drop a catalog target after this many consecutive discovery cycles with no response (0 = never purge)")
	statePath := fs.String("state", "", "persist miss counters (default: <out-alloy>.state.json)")
	if err := fs.Parse(argv); err != nil {
		return err
	}

	state := strings.TrimSpace(*statePath)
	if state == "" && strings.TrimSpace(*outAlloy) != "" {
		state = *outAlloy + ".state.json"
	}

	cat := newCatalog()
	p := scanParams{
		snmpCfg:     *snmpCfg,
		fpPath:      *fpPath,
		defaultFP:   *fpName,
		outAlloy:    *outAlloy,
		outSD:       *outSD,
		concurrency: *concurrency,
		timeout:     *timeout,
		retries:     *retries,
		defaultPort: uint16(*port),
		catalog:     cat,
		ping:        *ping,
		pingTimeout: *pingTimeout,
		misses:      *misses,
		statePath:   state,
	}

	if entries, err := readCatalogState(state); err == nil && len(entries) > 0 {
		cat.loadEntries(entries)
		log.Printf("loaded %d catalog entries from %s", len(entries), state)
	} else if prev, err := readAlloyYAML(*outAlloy); err == nil && len(prev) > 0 {
		cat.replace(prev)
		log.Printf("seeded catalog from %s (%d targets, miss counters reset)", *outAlloy, len(prev))
	}

	var scanMu sync.Mutex
	scanOnce := func() error {
		if !scanMu.TryLock() {
			log.Printf("previous scan still running; skip this tick")
			return nil
		}
		defer scanMu.Unlock()
		cfg, err := loadRunConfig(*configPath, *cidrs, *authsFlag, uint16(*port), *allowLarge, *fpName)
		if err != nil {
			return err
		}
		if err := mergeOverridesFile(&cfg, *overridesPath); err != nil {
			return err
		}
		return runScan(cfg, p)
	}

	if err := scanOnce(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if addr := strings.TrimSpace(*listen); addr != "" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		srv := &http.Server{
			Handler:           newDiscoveryMux(cat),
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Printf("HTTP SD on %s  GET /sd  GET /sd/prometheus  GET /alloy  GET /healthz", addr)
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("http: %v", err)
			}
		}()
		defer func() {
			shctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(shctx)
		}()
	}

	if *interval <= 0 {
		if strings.TrimSpace(*listen) == "" {
			return nil
		}
		<-ctx.Done()
		return nil
	}
	log.Printf("rescanning every %s (reload %s each pass)", *interval, nz(*configPath, "flags"))
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := scanOnce(); err != nil {
				log.Printf("scan error: %v", err)
			}
		}
	}
}

func loadRunConfig(configPath, cidrsCSV, authsCSV string, port uint16, allowLarge bool, fp string) (DiscoveryFile, error) {
	if strings.TrimSpace(configPath) != "" {
		return loadDiscoveryFile(configPath)
	}
	var cidrList []string
	for _, p := range strings.Split(cidrsCSV, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			cidrList = append(cidrList, p)
		}
	}
	if len(cidrList) == 0 {
		return DiscoveryFile{}, fmt.Errorf("--config or --cidrs is required")
	}
	var authNames []string
	for _, p := range strings.Split(authsCSV, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			authNames = append(authNames, p)
		}
	}
	if len(authNames) == 0 {
		return DiscoveryFile{}, fmt.Errorf("--auths is required in --cidrs mode (name the snmp.yml auth)")
	}
	return cliGroup("cli", cidrList, authNames, port, allowLarge, fp), nil
}

func mergeOverridesFile(cfg *DiscoveryFile, path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var extra DiscoveryFile
	if err := yaml.Unmarshal(b, &extra); err != nil {
		return fmt.Errorf("overrides %s: %w", path, err)
	}
	cfg.Overrides = append(cfg.Overrides, extra.Overrides...)
	return nil
}

func nz(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
