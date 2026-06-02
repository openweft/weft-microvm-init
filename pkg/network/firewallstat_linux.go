//go:build linux

package network

import (
	"fmt"

	nft "github.com/google/nftables"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// ReadFirewallStatus inspects the kernel "weft-fw" nftables table
// and returns a [[pod.FirewallStatus]] snapshot. PublishedAtUnix is
// left zero — the emitter stamps it just before publishing.
//
// Errors are folded into the returned status (Overall=Degraded,
// LastError=err.Error()) rather than propagated as a Go error. The
// emitter publishes status unconditionally ; a netlink hiccup
// shouldn't stop the next publish, and the operator wants the bad
// state on the dashboard rather than silent black-hole.
func ReadFirewallStatus() pod.FirewallStatus {
	c, err := nft.New(nft.AsLasting())
	if err != nil {
		return pod.FirewallStatus{Overall: "Degraded", LastError: fmt.Sprintf("nftables open: %v", err)}
	}
	defer c.CloseLasting()

	tables, err := c.ListTablesOfFamily(nft.TableFamilyINet)
	if err != nil {
		return pod.FirewallStatus{Overall: "Degraded", LastError: fmt.Sprintf("list tables: %v", err)}
	}
	var ourTable *nft.Table
	for _, t := range tables {
		if t.Name == firewallTableName {
			ourTable = t
			break
		}
	}
	if ourTable == nil {
		// No table yet — agent is up, reconciler hasn't received a
		// desired-state publish. Healthy idle.
		return pod.FirewallStatus{Overall: "Healthy"}
	}

	chains, err := c.ListChainsOfTableFamily(nft.TableFamilyINet)
	if err != nil {
		return pod.FirewallStatus{
			Overall:        "Degraded",
			TableInstalled: true,
			LastError:      fmt.Sprintf("list chains: %v", err),
		}
	}
	total := 0
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name != firewallTableName {
			continue
		}
		rules, err := c.GetRules(ourTable, ch)
		if err != nil {
			return pod.FirewallStatus{
				Overall:        "Degraded",
				TableInstalled: true,
				LastError:      fmt.Sprintf("get rules in %s: %v", ch.Name, err),
			}
		}
		total += len(rules)
	}
	return pod.FirewallStatus{
		Overall:        "Healthy",
		TableInstalled: true,
		RulesInstalled: total,
	}
}
