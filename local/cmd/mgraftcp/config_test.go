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
}

func TestClientArgsIncludesDNSPortWhenEnabled(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"mgraftcp"}
	defer func() { os.Args = oldArgs }()

	cfg := defaultConfig()
	cfg.dnsProxy = true

	got := cfg.clientArgs(2233, 5353, []string{"curl", "example.com"})
	want := []string{"mgraftcp", "-p", "2233", "--dns-port", "5353", "curl", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("clientArgs() = %v, want %v", got, want)
	}
}
