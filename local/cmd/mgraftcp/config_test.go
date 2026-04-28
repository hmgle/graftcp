package main

import (
	"os"
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
