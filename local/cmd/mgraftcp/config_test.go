package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConfigDNSOptions(t *testing.T) {
	cfg := defaultConfig()

	if cfg.dnsProxy {
		t.Fatal("defaultConfig() enabled DNS proxy")
	}
	if cfg.dnsServer != "1.1.1.1:53" {
		t.Fatalf("default dnsServer = %q, want %q", cfg.dnsServer, "1.1.1.1:53")
	}

	cfg.set("dns_proxy", "true")
	cfg.set("dns_server", "8.8.8.8:53")
	if !cfg.dnsProxy {
		t.Fatal("dns_proxy=true did not enable DNS proxy")
	}
	if cfg.dnsServer != "8.8.8.8:53" {
		t.Fatalf("dnsServer = %q, want %q", cfg.dnsServer, "8.8.8.8:53")
	}
}

func TestConfigUDPOptions(t *testing.T) {
	cfg := defaultConfig()

	if cfg.udpProxy {
		t.Fatal("defaultConfig() enabled UDP proxy")
	}
	cfg.set("udp_proxy", "true")
	if !cfg.udpProxy {
		t.Fatal("udp_proxy=true did not enable UDP proxy")
	}
}

func TestDNSConfigFlagOverrides(t *testing.T) {
	flagset := map[string]bool{"enable-dns": true}
	if !configKeyOverriddenByFlag(flagset, "dns_proxy") {
		t.Fatal("enable-dns did not override dns_proxy config")
	}

	flagset = map[string]bool{"disable-dns": true}
	if !configKeyOverriddenByFlag(flagset, "enable_dns") {
		t.Fatal("disable-dns did not override enable_dns config")
	}

	flagset = map[string]bool{"dns-server": true}
	if !configKeyOverriddenByFlag(flagset, "dns_server") {
		t.Fatal("dns-server did not override dns_server config")
	}

	flagset = map[string]bool{"enable-udp": true}
	if !configKeyOverriddenByFlag(flagset, "udp_proxy") {
		t.Fatal("enable-udp did not override udp_proxy config")
	}

	flagset = map[string]bool{"disable-udp": true}
	if !configKeyOverriddenByFlag(flagset, "enable_udp") {
		t.Fatal("disable-udp did not override enable_udp config")
	}
}

func TestClientArgsIncludesProxyPortsWhenEnabled(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"mgraftcp"}
	defer func() { os.Args = oldArgs }()

	cfg := defaultConfig()
	cfg.dnsProxy = true
	cfg.udpProxy = true

	got := cfg.clientArgs(2233, 5353, 5354, []string{"curl", "example.com"})
	want := []string{"mgraftcp", "-p", "2233", "--dns-port", "5353", "--udp-port", "5354", "curl", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clientArgs() = %v, want %v", got, want)
	}
}

func TestParseConfigFileLoadsValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mgraftcp.conf")
	body := "" +
		"# comment line\n" +
		"socks5 = 10.0.0.1:1080\n" +
		"socks5_username=alice\n" +
		"socks5_password=secret\n" +
		"enable-dns = true\n" +
		"dns_server = 9.9.9.9:53\n" +
		"enable_udp= 1\n" +
		"http_proxy =127.0.0.1:8080\n" +
		"select_proxy_mode= only_socks5\n" +
		"not_ignore_local=on\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg := defaultConfig()
	if err := cfg.parseConfigFile(path); err != nil {
		t.Fatalf("parseConfigFile() error = %v", err)
	}
	if cfg.socks5Addr != "10.0.0.1:1080" {
		t.Fatalf("socks5Addr = %q", cfg.socks5Addr)
	}
	if cfg.socks5User != "alice" || cfg.socks5Pwd != "secret" {
		t.Fatalf("socks5 user/pwd = %q/%q", cfg.socks5User, cfg.socks5Pwd)
	}
	if !cfg.dnsProxy || cfg.dnsServer != "9.9.9.9:53" {
		t.Fatalf("dns config not loaded: dnsProxy=%v dnsServer=%q", cfg.dnsProxy, cfg.dnsServer)
	}
	if !cfg.udpProxy {
		t.Fatal("udpProxy not loaded")
	}
	if cfg.httpProxyAddr != "127.0.0.1:8080" {
		t.Fatalf("httpProxyAddr = %q", cfg.httpProxyAddr)
	}
	if cfg.selectProxyMode != "only_socks5" {
		t.Fatalf("selectProxyMode = %q", cfg.selectProxyMode)
	}
	if !cfg.notIgnoreLocal {
		t.Fatal("notIgnoreLocal not loaded")
	}
}

func TestParseConfigFileTrailingNewlineDoesNotDoubleParse(t *testing.T) {
	dir := t.TempDir()
	with := filepath.Join(dir, "with.conf")
	without := filepath.Join(dir, "without.conf")
	if err := os.WriteFile(with, []byte("dns_server = 1.0.0.1:53\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(without, []byte("dns_server = 1.0.0.1:53"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	for _, p := range []string{with, without} {
		cfg := defaultConfig()
		if err := cfg.parseConfigFile(p); err != nil {
			t.Fatalf("parseConfigFile(%s) error = %v", p, err)
		}
		if cfg.dnsServer != "1.0.0.1:53" {
			t.Fatalf("parseConfigFile(%s) dnsServer = %q", p, cfg.dnsServer)
		}
	}
}

func TestParseBoolUnknownValueLeavesFieldUnchanged(t *testing.T) {
	cfg := defaultConfig()
	cfg.dnsProxy = true
	cfg.set("enable_dns", "garbage")
	if !cfg.dnsProxy {
		t.Fatal("invalid bool value should not flip enable_dns")
	}
}
