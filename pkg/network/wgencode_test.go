package network

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// parseAttrs walks a flat sequence of netlink attributes into type→value,
// stripping the nested flag from the type and skipping inter-attribute
// padding. Duplicate types (array elements) collapse to the last seen, so
// tests that need every element walk manually instead.
func parseAttrs(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		l := binary.LittleEndian.Uint16(b[0:2])
		typ := binary.LittleEndian.Uint16(b[2:4]) &^ nlaFNested
		if int(l) < 4 || int(l) > len(b) {
			break
		}
		out[typ] = b[4:l]
		adv := (int(l) + 3) &^ 3 // round up to 4
		b = b[adv:]
	}
	return out
}

// arrayEntries splits a nested array attribute payload into its element
// payloads in order (element attr type == index).
func arrayEntries(b []byte) [][]byte {
	var entries [][]byte
	for len(b) >= 4 {
		l := binary.LittleEndian.Uint16(b[0:2])
		if int(l) < 4 || int(l) > len(b) {
			break
		}
		entries = append(entries, b[4:l])
		adv := (int(l) + 3) &^ 3
		b = b[adv:]
	}
	return entries
}

func TestEncodeSetDevice_Structure(t *testing.T) {
	priv := bytes.Repeat([]byte{0x11}, keyLen)
	pub := bytes.Repeat([]byte{0x22}, keyLen)

	d := wgDevice{
		ifindex:    7,
		privateKey: priv,
		listenPort: 51820,
		peers: []wgPeer{{
			publicKey: pub,
			endpoint:  &wgEndpoint{ip: net.ParseIP("203.0.113.5"), port: 51821},
			keepalive: 25,
			allowedIPs: []wgAllowedIP{
				{ip: net.ParseIP("10.9.0.2"), cidr: 32},
			},
		}},
	}

	msg, err := encodeSetDevice(d)
	if err != nil {
		t.Fatalf("encodeSetDevice: %v", err)
	}

	// genlmsghdr.
	if msg[0] != wgCmdSetDevice || msg[1] != wgGenlVersion {
		t.Fatalf("genl header = %v, want cmd=%d ver=%d", msg[0:2], wgCmdSetDevice, wgGenlVersion)
	}

	attrs := parseAttrs(msg[4:])

	if got := binary.LittleEndian.Uint32(attrs[wgdeviceAIfindex]); got != 7 {
		t.Errorf("ifindex = %d, want 7", got)
	}
	if got := binary.LittleEndian.Uint32(attrs[wgdeviceAFlags]); got != wgdeviceFReplacePeers {
		t.Errorf("device flags = %d, want replace-peers", got)
	}
	if !bytes.Equal(attrs[wgdeviceAPrivateKey], priv) {
		t.Errorf("private key not round-tripped")
	}
	if got := binary.LittleEndian.Uint16(attrs[wgdeviceAListenPort]); got != 51820 {
		t.Errorf("listen port = %d, want 51820", got)
	}

	peers := arrayEntries(attrs[wgdeviceAPeers])
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	pa := parseAttrs(peers[0])
	if !bytes.Equal(pa[wgpeerAPublicKey], pub) {
		t.Errorf("peer public key not round-tripped")
	}
	if got := binary.LittleEndian.Uint32(pa[wgpeerAFlags]); got != wgpeerFReplaceAllowedips {
		t.Errorf("peer flags = %d, want replace-allowedips", got)
	}
	if got := binary.LittleEndian.Uint16(pa[wgpeerAPersistentKeepaliveInterval]); got != 25 {
		t.Errorf("keepalive = %d, want 25", got)
	}

	// Endpoint: sockaddr_in — family LE, port BE, addr network order.
	ep := pa[wgpeerAEndpoint]
	if len(ep) != 16 {
		t.Fatalf("endpoint len = %d, want 16 (sockaddr_in)", len(ep))
	}
	if fam := binary.LittleEndian.Uint16(ep[0:2]); fam != afInet {
		t.Errorf("endpoint family = %d, want %d", fam, afInet)
	}
	if port := binary.BigEndian.Uint16(ep[2:4]); port != 51821 {
		t.Errorf("endpoint port = %d, want 51821", port)
	}
	if !bytes.Equal(ep[4:8], net.ParseIP("203.0.113.5").To4()) {
		t.Errorf("endpoint addr = %v", ep[4:8])
	}

	aips := arrayEntries(pa[wgpeerAAllowedips])
	if len(aips) != 1 {
		t.Fatalf("expected 1 allowed-ip, got %d", len(aips))
	}
	aa := parseAttrs(aips[0])
	if fam := binary.LittleEndian.Uint16(aa[wgallowedipAFamily]); fam != afInet {
		t.Errorf("allowed-ip family = %d, want %d", fam, afInet)
	}
	if !bytes.Equal(aa[wgallowedipAIpaddr], net.ParseIP("10.9.0.2").To4()) {
		t.Errorf("allowed-ip addr = %v", aa[wgallowedipAIpaddr])
	}
	if aa[wgallowedipACidrMask][0] != 32 {
		t.Errorf("allowed-ip cidr = %d, want 32", aa[wgallowedipACidrMask][0])
	}
}

func TestEncodeSetDevice_BadKeyLen(t *testing.T) {
	if _, err := encodeSetDevice(wgDevice{privateKey: []byte{1, 2, 3}}); err == nil {
		t.Error("expected error for short private key")
	}
}

func TestNlaPaddingAndLength(t *testing.T) {
	// A 1-byte payload → header(4)+1 = len field 5, padded to 8 bytes total.
	a := nlaU8(wgallowedipACidrMask, 24)
	if got := binary.LittleEndian.Uint16(a[0:2]); got != 5 {
		t.Errorf("attr len field = %d, want 5", got)
	}
	if len(a) != 8 {
		t.Errorf("padded len = %d, want 8", len(a))
	}
}
