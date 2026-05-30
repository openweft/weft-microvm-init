//go:build linux

// wireguard_linux.go brings up a kernel WireGuard interface (wg0) entirely
// via netlink — rtnetlink to create the link and assign its address, and
// generic netlink to push the device config (private key, listen port,
// peers). No `wg`/`ip` binaries, no third-party deps, matching netlink.go.
package network

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// rtnetlink / genetlink attribute numbers used here.
const (
	iflaIfname   = 3
	iflaLinkinfo = 18
	iflaInfoKind = 1

	genlIDCtrl         = 0x10
	ctrlCmdGetFamily   = 3
	ctrlAttrFamilyID   = 1
	ctrlAttrFamilyName = 2
)

// ApplyWireGuard creates the WireGuard interface, configures its device
// (key, port, peers) and brings it up with the overlay address. Idempotent:
// re-applying replaces peers and re-asserts the address.
func ApplyWireGuard(wg *pod.WireGuard) error {
	if wg == nil {
		return nil
	}
	iface := wg.Interface
	if iface == "" {
		iface = "wg0"
	}

	priv, err := base64.StdEncoding.DecodeString(wg.PrivateKey)
	if err != nil {
		return fmt.Errorf("wireguard private_key: %w", err)
	}
	if len(priv) != keyLen {
		return fmt.Errorf("wireguard private_key must be %d bytes, got %d", keyLen, len(priv))
	}

	if err := createWGLink(iface); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("create %s: %w", iface, err)
	}

	idx, err := ifaceIndex(iface)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", iface, err)
	}

	dev, err := buildDevice(idx, priv, wg)
	if err != nil {
		return err
	}
	payload, err := encodeSetDevice(dev)
	if err != nil {
		return err
	}
	if err := setDevice(payload); err != nil {
		return fmt.Errorf("configure %s: %w", iface, err)
	}

	if err := linkUp(idx); err != nil {
		return fmt.Errorf("link up %s: %w", iface, err)
	}
	if wg.Address != "" {
		ip, ipnet, err := net.ParseCIDR(wg.Address)
		if err != nil {
			return fmt.Errorf("wireguard address %q: %w", wg.Address, err)
		}
		// Assigning with the prefix installs the connected route, so peers
		// inside the overlay subnet are reachable without an explicit route.
		if err := addrAdd(idx, ip, ipnet); err != nil && !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("addr add %s on %s: %w", wg.Address, iface, err)
		}
	}
	return nil
}

// buildDevice translates the pod spec into the encoder's device model.
func buildDevice(idx int32, priv []byte, wg *pod.WireGuard) (wgDevice, error) {
	dev := wgDevice{
		ifindex:    idx,
		privateKey: priv,
		listenPort: wg.ListenPort,
	}
	for i, p := range wg.Peers {
		pub, err := base64.StdEncoding.DecodeString(p.PublicKey)
		if err != nil || len(pub) != keyLen {
			return wgDevice{}, fmt.Errorf("peer %d public_key: invalid base64/length", i)
		}
		peer := wgPeer{publicKey: pub, keepalive: p.PersistentKeepalive}
		if p.Endpoint != "" {
			ua, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return wgDevice{}, fmt.Errorf("peer %d endpoint %q: %w", i, p.Endpoint, err)
			}
			peer.endpoint = &wgEndpoint{ip: ua.IP, port: uint16(ua.Port)}
		}
		for _, cidr := range p.AllowedIPs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return wgDevice{}, fmt.Errorf("peer %d allowed_ip %q: %w", i, cidr, err)
			}
			ones, _ := ipnet.Mask.Size()
			peer.allowedIPs = append(peer.allowedIPs, wgAllowedIP{ip: ipnet.IP, cidr: uint8(ones)})
		}
		dev.peers = append(dev.peers, peer)
	}
	return dev, nil
}

// createWGLink issues RTM_NEWLINK with link-kind "wireguard" so the kernel
// instantiates the device.
func createWGLink(name string) error {
	type ifinfomsg struct {
		Family uint8
		_      uint8
		Type   uint16
		Index  int32
		Flags  uint32
		Change uint32
	}
	body := ifinfomsg{Family: syscall.AF_UNSPEC}

	msg := newMessage(syscall.RTM_NEWLINK, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
	msg.append((*[unsafe.Sizeof(ifinfomsg{})]byte)(unsafe.Pointer(&body))[:])
	msg.buf = append(msg.buf, nlaStr(iflaIfname, name)...)
	msg.buf = append(msg.buf, nlaNested(iflaLinkinfo, nlaStr(iflaInfoKind, wgGenlName))...)
	return talk(msg.bytes())
}

// setDevice sends the WG_CMD_SET_DEVICE payload to the resolved "wireguard"
// generic-netlink family.
func setDevice(payload []byte) error {
	family, err := resolveGenlFamily(wgGenlName)
	if err != nil {
		return err
	}
	msg := newMessage(family, syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	msg.append(payload)
	_, err = genlRoundtrip(msg.bytes())
	return err
}

// resolveGenlFamily looks up a generic-netlink family id by name via the
// controller.
func resolveGenlFamily(name string) (uint16, error) {
	payload := genlHeader(ctrlCmdGetFamily, 1)
	payload = append(payload, nlaStr(ctrlAttrFamilyName, name)...)
	msg := newMessage(genlIDCtrl, syscall.NLM_F_REQUEST)
	msg.append(payload)

	frames, err := genlRoundtrip(msg.bytes())
	if err != nil {
		return 0, err
	}
	for _, data := range frames {
		if len(data) < 4 {
			continue
		}
		// Skip genlmsghdr (4 bytes), then walk attributes for FAMILY_ID.
		attrs := data[4:]
		for len(attrs) >= 4 {
			l := int(hostUint16(attrs[0:2]))
			typ := hostUint16(attrs[2:4]) &^ nlaFNested
			if l < 4 || l > len(attrs) {
				break
			}
			if typ == ctrlAttrFamilyID {
				return hostUint16(attrs[4:6]), nil
			}
			adv := (l + 3) &^ 3
			attrs = attrs[adv:]
		}
	}
	return 0, fmt.Errorf("genl family %q not found", name)
}

// genlRoundtrip sends one request on a NETLINK_GENERIC socket and returns the
// payloads of the reply frames (the genl message after each nlmsghdr). An
// NLMSG_ERROR with a non-zero errno is returned as an error; errno 0 is an
// ack and yields no frames.
func genlRoundtrip(req []byte) ([][]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}

	buf := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return nil, err
	}
	var frames [][]byte
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return nil, fmt.Errorf("short NLMSG_ERROR")
			}
			if errno := int32(hostUint32(m.Data[0:4])); errno != 0 {
				return nil, syscall.Errno(-errno)
			}
			// errno 0 == ack.
		case syscall.NLMSG_DONE:
			return frames, nil
		default:
			frames = append(frames, m.Data)
		}
	}
	return frames, nil
}

func hostUint16(b []byte) uint16 { return *(*uint16)(unsafe.Pointer(&b[0])) }
func hostUint32(b []byte) uint32 { return *(*uint32)(unsafe.Pointer(&b[0])) }
