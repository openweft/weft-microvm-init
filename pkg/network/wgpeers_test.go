package network

import (
	"bytes"
	"encoding/base64"
	"net"
	"testing"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

func TestBuildPeers_Roundtrip(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, keyLen))

	out, err := buildPeers([]pod.WGPeer{{
		PublicKey:           pub,
		Endpoint:            "203.0.113.5:51821",
		AllowedIPs:          []string{"10.9.0.2/32", "10.9.1.0/24"},
		PersistentKeepalive: 25,
	}})
	if err != nil {
		t.Fatalf("buildPeers: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(out))
	}
	p := out[0]
	if p.PublicKey != pub {
		t.Errorf("pubkey = %q, want %q", p.PublicKey, pub)
	}
	if p.Endpoint != "203.0.113.5:51821" {
		t.Errorf("endpoint = %q", p.Endpoint)
	}
	if len(p.AllowedIPs) != 2 {
		t.Errorf("allowed-ips = %d, want 2", len(p.AllowedIPs))
	}
	if p.AllowedIPs[0].String() != "10.9.0.2/32" || p.AllowedIPs[1].String() != "10.9.1.0/24" {
		t.Errorf("allowed-ips = %v", p.AllowedIPs)
	}
	if p.PersistentKeepalive != 25 {
		t.Errorf("keepalive = %d", p.PersistentKeepalive)
	}
}

func TestBuildPeers_BadPubkey(t *testing.T) {
	if _, err := buildPeers([]pod.WGPeer{{PublicKey: "not-base64"}}); err == nil {
		t.Error("expected error for bad pubkey")
	}
}

func TestBuildPeers_BadAllowedIP(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, keyLen))
	if _, err := buildPeers([]pod.WGPeer{{PublicKey: pub, AllowedIPs: []string{"nope"}}}); err == nil {
		t.Error("expected error for bad allowed-ip")
	}
}

func TestOverlayLocalIP_IPv4(t *testing.T) {
	ip := net.ParseIP("10.9.0.1")
	a, err := overlayLocalIP(ip)
	if err != nil {
		t.Fatalf("overlayLocalIP: %v", err)
	}
	if a.String() != "10.9.0.1" {
		t.Errorf("got %q, want 10.9.0.1", a.String())
	}
	if !a.Is4() {
		t.Error("expected unmapped IPv4")
	}
}

func TestOverlayLocalIP_Nil(t *testing.T) {
	if _, err := overlayLocalIP(nil); err == nil {
		t.Error("expected error for nil IP")
	}
}
