// wgencode.go builds the generic-netlink payload that configures a kernel
// WireGuard device (WG_CMD_SET_DEVICE), framing the WGDEVICE / WGPEER /
// WGALLOWEDIP nested attributes by hand against the linux/wireguard.h uABI.
//
// It is deliberately free of syscalls and build constraints so the wire
// encoding is unit-testable on any OS; wireguard_linux.go does the actual
// netlink socket I/O.
package network

import (
	"encoding/binary"
	"fmt"
	"net"
)

// WireGuard generic-netlink command + attribute numbers (linux/wireguard.h).
const (
	wgGenlName    = "wireguard"
	wgGenlVersion = 1

	wgCmdSetDevice = 1

	wgdeviceAIfindex    = 1
	wgdeviceAPrivateKey = 3
	wgdeviceAFlags      = 5
	wgdeviceAListenPort = 6
	wgdeviceAPeers      = 8

	wgdeviceFReplacePeers = 1 << 0

	wgpeerAPublicKey                   = 1
	wgpeerAFlags                       = 3
	wgpeerAEndpoint                    = 4
	wgpeerAPersistentKeepaliveInterval = 5
	wgpeerAAllowedips                  = 9

	wgpeerFReplaceAllowedips = 1 << 1

	wgallowedipAFamily   = 1
	wgallowedipAIpaddr   = 2
	wgallowedipACidrMask = 3
)

// nlaFNested is the netlink attribute flag marking a nested attribute
// (linux/netlink.h NLA_F_NESTED).
const nlaFNested = 0x8000

// keyLen is the size of a Curve25519 WireGuard key.
const keyLen = 32

// wgDevice is the in-memory description encodeSetDevice turns into the
// WG_CMD_SET_DEVICE payload.
type wgDevice struct {
	ifindex    int32
	privateKey []byte // 32 bytes
	listenPort uint16
	peers      []wgPeer
}

type wgPeer struct {
	publicKey  []byte // 32 bytes
	endpoint   *wgEndpoint
	keepalive  uint16
	allowedIPs []wgAllowedIP
}

type wgEndpoint struct {
	ip   net.IP
	port uint16
}

type wgAllowedIP struct {
	ip   net.IP
	cidr uint8
}

// encodeSetDevice renders the genetlink payload (genlmsghdr followed by the
// WGDEVICE attribute tree) for WG_CMD_SET_DEVICE. The caller wraps it in an
// nlmsghdr addressed to the resolved "wireguard" family.
func encodeSetDevice(d wgDevice) ([]byte, error) {
	if len(d.privateKey) != keyLen {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", keyLen, len(d.privateKey))
	}

	buf := genlHeader(wgCmdSetDevice, wgGenlVersion)

	buf = append(buf, nlaU32(wgdeviceAIfindex, uint32(d.ifindex))...)
	// Replace the whole peer set on each apply — the spec is authoritative.
	buf = append(buf, nlaU32(wgdeviceAFlags, wgdeviceFReplacePeers)...)
	buf = append(buf, nlaBytes(wgdeviceAPrivateKey, d.privateKey)...)
	if d.listenPort != 0 {
		buf = append(buf, nlaU16(wgdeviceAListenPort, d.listenPort)...)
	}

	if len(d.peers) > 0 {
		peerEntries := make([][]byte, 0, len(d.peers))
		for i, p := range d.peers {
			enc, err := encodePeer(p)
			if err != nil {
				return nil, fmt.Errorf("peer %d: %w", i, err)
			}
			// Array element: attr type = index, nested.
			peerEntries = append(peerEntries, nlaNested(uint16(i), enc))
		}
		buf = append(buf, nlaNested(wgdeviceAPeers, peerEntries...)...)
	}

	return buf, nil
}

func encodePeer(p wgPeer) ([]byte, error) {
	if len(p.publicKey) != keyLen {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", keyLen, len(p.publicKey))
	}
	var buf []byte
	buf = append(buf, nlaBytes(wgpeerAPublicKey, p.publicKey)...)
	// Replace allowed-ips wholesale to match the spec.
	buf = append(buf, nlaU32(wgpeerAFlags, wgpeerFReplaceAllowedips)...)
	if p.endpoint != nil {
		sa, err := encodeSockaddr(p.endpoint.ip, p.endpoint.port)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nlaBytes(wgpeerAEndpoint, sa)...)
	}
	if p.keepalive != 0 {
		buf = append(buf, nlaU16(wgpeerAPersistentKeepaliveInterval, p.keepalive)...)
	}
	if len(p.allowedIPs) > 0 {
		entries := make([][]byte, 0, len(p.allowedIPs))
		for i, a := range p.allowedIPs {
			enc, err := encodeAllowedIP(a)
			if err != nil {
				return nil, fmt.Errorf("allowed-ip %d: %w", i, err)
			}
			entries = append(entries, nlaNested(uint16(i), enc))
		}
		buf = append(buf, nlaNested(wgpeerAAllowedips, entries...)...)
	}
	return buf, nil
}

func encodeAllowedIP(a wgAllowedIP) ([]byte, error) {
	fam, raw, err := ipFamily(a.ip)
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = append(buf, nlaU16(wgallowedipAFamily, fam)...)
	buf = append(buf, nlaBytes(wgallowedipAIpaddr, raw)...)
	buf = append(buf, nlaU8(wgallowedipACidrMask, a.cidr)...)
	return buf, nil
}

// encodeSockaddr renders a struct sockaddr_in / sockaddr_in6 as the kernel
// expects in WGPEER_A_ENDPOINT: family in host byte order, port and address
// in network byte order.
func encodeSockaddr(ip net.IP, port uint16) ([]byte, error) {
	if v4 := ip.To4(); v4 != nil {
		b := make([]byte, 16) // sizeof(struct sockaddr_in)
		binary.LittleEndian.PutUint16(b[0:2], afInet)
		binary.BigEndian.PutUint16(b[2:4], port)
		copy(b[4:8], v4)
		return b, nil
	}
	if v6 := ip.To16(); v6 != nil {
		b := make([]byte, 28) // sizeof(struct sockaddr_in6)
		binary.LittleEndian.PutUint16(b[0:2], afInet6)
		binary.BigEndian.PutUint16(b[2:4], port)
		// b[4:8] sin6_flowinfo = 0
		copy(b[8:24], v6)
		// b[24:28] sin6_scope_id = 0
		return b, nil
	}
	return nil, fmt.Errorf("invalid endpoint IP %v", ip)
}

func ipFamily(ip net.IP) (uint16, []byte, error) {
	if v4 := ip.To4(); v4 != nil {
		return afInet, v4, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return afInet6, v6, nil
	}
	return 0, nil, fmt.Errorf("invalid IP %v", ip)
}

// afInet / afInet6 are the Linux address-family numbers (the build host may
// differ, so they're fixed here rather than taken from syscall).
const (
	afInet  = 2
	afInet6 = 10
)

// --- netlink attribute primitives ---------------------------------------
//
// Each attribute is: uint16 len (header+payload, excluding trailing pad) |
// uint16 type | payload | pad-to-4. Numeric payloads use host byte order
// (little-endian on the supported archs).

func genlHeader(cmd, version uint8) []byte {
	// struct genlmsghdr { __u8 cmd; __u8 version; __u16 reserved; }
	return []byte{cmd, version, 0, 0}
}

func nlaBytes(typ uint16, value []byte) []byte {
	total := 4 + len(value)
	out := make([]byte, total)
	binary.LittleEndian.PutUint16(out[0:2], uint16(total))
	binary.LittleEndian.PutUint16(out[2:4], typ)
	copy(out[4:], value)
	return pad4(out)
}

func nlaStr(typ uint16, s string) []byte {
	return nlaBytes(typ, append([]byte(s), 0)) // NUL-terminated
}

func nlaU8(typ uint16, v uint8) []byte { return nlaBytes(typ, []byte{v}) }
func nlaU16(typ uint16, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return nlaBytes(typ, b)
}
func nlaU32(typ uint16, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return nlaBytes(typ, b)
}

// nlaNested wraps already-encoded child attributes in a nested attribute.
func nlaNested(typ uint16, children ...[]byte) []byte {
	var payload []byte
	for _, c := range children {
		payload = append(payload, c...)
	}
	return nlaBytes(typ|nlaFNested, payload)
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
