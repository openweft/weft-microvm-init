# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
