# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-11-25

### Added

- **Boot-token provider** : `secretclient.FileTokenSource` reads the per-boot
  GuestSecrets token once from the QEMU fw_cfg entry
  (`/sys/firmware/qemu_fw_cfg/by_name/opt/org.weft/boot-token/raw`, exactly
  32 raw bytes), keeps it in memory only and sends it as
  `FetchRequest.boot_token`. An absent file means no token; any other length
  is an error and nothing is sent. `weft-init` uses it by default.

## [0.4.0] - 2026-11-25

### Added

- **`pkg/secretclient`**: guest client for `weft.guest.v1.GuestSecrets/Fetch`
  (weft-proto v0.24.0) over the host vsock port. Bounded retries with
  exponential backoff on `Unavailable` / `ResourceExhausted` / a failed dial;
  `PermissionDenied` (also "no such id") is final; a value over 64 KiB is
  refused; error text is constant and never carries a value or token. The
  per-boot token comes from a pluggable `TokenSource` (empty or exactly 32
  bytes) and is sent when present.
- **`private_key_ref`** on `pod.WireGuard` and **`access_key_ref` /
  `secret_key_ref` / `secret_version`** on `pod.CubeFSMount`: the key is
  fetched over vsock instead of read from the spec. The WireGuard key is
  staged to a 0600 file under `/run` (tmpfs) and the in-memory copies are
  wiped; the cfs-client config stays 0600 and its rendered buffer is wiped.
  `network.ApplyWireGuardWith` and `cubefs.Resolve` /
  `cubefs.NewRegistryWithSecrets` take the secret source.

### Changed

- Setting a ref together with its inline field is now an error. Inline keys
  still work in this release and log a deprecation warning; they will be
  refused in a later release.
- A CubeFS mount resolves its keys before touching an existing mount, so a
  failed fetch leaves the old mount up.

## [0.2.3] - 2026-06-14

### Added

- **`pod.FirewallStatus` type + `network.ReadFirewallStatus`** : the
  wire shape `weft-microvm-agent`'s emitter publishes on
  `weft.firewall.<vm-id>.status` so the control plane (and the UI)
  can see whether the in-VM nftables reconciler is healthy and how
  many rules are installed right now. `ReadFirewallStatus` (linux)
  walks the kernel `weft-fw` table via
  `ListChainsOfTableFamily` + `GetRules` and sums rule counts ;
  failures fold into a `Degraded` status (with `LastError`) rather
  than propagating, so the emitter publishes the bad state instead
  of black-holing. Commit `74d4de7`.

## [0.2.0] - 2026-06-02

### Added

- **`pod.Firewall` type + nftables reconciler** :
  `pod.Firewall` / `pod.FirewallRule` mirror the `weft-proto`
  `SecurityRule` shape with `remote_group_uuid` already
  dereferenced to `RemoteCIDR`. `network.ApplyFirewall` is a
  whole-state reconciler that converges the kernel `weft-fw`
  inet table : replace-set per netlink batch, same pattern as
  the existing WireGuard apply, so a missed publish self-heals
  on the next message. `ct established,related accept` sits
  unconditional at the top of the input chain so reply traffic
  for VM-initiated egress flows in without a mirrored ingress
  rule. Linux-only via filename suffix split
  (`firewall_linux.go` / `firewall_other.go` stub) so the agent
  still builds on darwin for host-side dev. Commit `fb45bc4`.

## [0.1.0] - 2026-05-31

Initial release. PID-1 init for weft microVMs : minimal FS
mounts, ifup, launches `weft-microvm-agent`. No systemd. BSD
3-Clause LICENSE (`9095de7`).
