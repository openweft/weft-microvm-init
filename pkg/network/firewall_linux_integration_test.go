//go:build linux && integration

// firewall_linux_integration_test.go drives ApplyFirewall against a
// real Linux kernel and reads the resulting nftables table back via
// github.com/google/nftables to assert chains, policies, and rule
// counts.
//
// Run with :
//   sudo -E env "PATH=$PATH" go test -tags=integration ./pkg/network/
//
// The test runs inside a fresh network namespace so the ruleset it
// installs never leaks onto the CI host. CAP_NET_ADMIN is required.

package network

import (
	"errors"
	"os"
	"runtime"
	"testing"

	nft "github.com/google/nftables"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/openweft/weft-microvm-init/pkg/pod"
)

// enterFreshNetns pins the calling goroutine to its OS thread and
// switches it into a brand-new empty network namespace. Caller MUST
// defer the returned cleanup.
func enterFreshNetns(t *testing.T) func() {
	t.Helper()
	runtime.LockOSThread()

	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatalf("netns.Get: %v", err)
	}
	fresh, err := netns.New()
	if err != nil {
		_ = orig.Close()
		runtime.UnlockOSThread()
		if errors.Is(err, unix.EPERM) || os.Geteuid() != 0 {
			t.Skipf("creating a netns requires CAP_NET_ADMIN (try `sudo go test -tags=integration`): %v", err)
		}
		t.Fatalf("netns.New: %v", err)
	}

	return func() {
		_ = netns.Set(orig)
		_ = fresh.Close()
		_ = orig.Close()
		runtime.UnlockOSThread()
	}
}

func TestApplyFirewall_BaselineInstallsTableWithDefaultDenyInput(t *testing.T) {
	cleanup := enterFreshNetns(t)
	defer cleanup()

	if err := ApplyFirewall(&pod.Firewall{}); err != nil {
		t.Fatalf("ApplyFirewall(empty): %v", err)
	}

	tb, input, output := readFirewallLayout(t)
	if tb == nil {
		t.Fatalf("expected inet table %q to be installed", firewallTableName)
	}
	if input == nil || output == nil {
		t.Fatalf("expected input + output chains, got input=%v output=%v", input, output)
	}
	if input.Policy == nil || *input.Policy != nft.ChainPolicyDrop {
		t.Errorf("input policy = %v, want drop", input.Policy)
	}
	if output.Policy == nil || *output.Policy != nft.ChainPolicyAccept {
		t.Errorf("output policy = %v, want accept", output.Policy)
	}

	c, _ := nft.New(nft.AsLasting())
	defer c.CloseLasting()

	inRules, err := c.GetRules(tb, input)
	if err != nil {
		t.Fatalf("GetRules(input): %v", err)
	}
	// Baseline = ct established/related accept + iifname lo accept.
	if len(inRules) != 2 {
		t.Errorf("baseline input rule count = %d, want 2", len(inRules))
	}
	outRules, err := c.GetRules(tb, output)
	if err != nil {
		t.Fatalf("GetRules(output): %v", err)
	}
	if len(outRules) != 0 {
		t.Errorf("baseline output rule count = %d, want 0", len(outRules))
	}
}

func TestApplyFirewall_AddsIngressRulesOnTopOfBaseline(t *testing.T) {
	cleanup := enterFreshNetns(t)
	defer cleanup()

	fw := &pod.Firewall{
		Rules: []pod.FirewallRule{
			{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22, RemoteCIDR: "10.0.0.0/8"},
			{Direction: "ingress", Protocol: "tcp", PortMin: 80, PortMax: 80},
			{Direction: "ingress", Protocol: "icmp"},
		},
	}
	if err := ApplyFirewall(fw); err != nil {
		t.Fatalf("ApplyFirewall: %v", err)
	}

	tb, input, output := readFirewallLayout(t)
	c, _ := nft.New(nft.AsLasting())
	defer c.CloseLasting()

	inRules, err := c.GetRules(tb, input)
	if err != nil {
		t.Fatalf("GetRules(input): %v", err)
	}
	// 2 baseline rules + 3 user-supplied ingress rules.
	if got, want := len(inRules), 2+3; got != want {
		t.Errorf("input rule count = %d, want %d", got, want)
	}

	outRules, err := c.GetRules(tb, output)
	if err != nil {
		t.Fatalf("GetRules(output): %v", err)
	}
	if len(outRules) != 0 {
		t.Errorf("output rule count = %d, want 0 (no egress in fixture)", len(outRules))
	}
}

func TestApplyFirewall_RoutesEgressRulesToOutputChain(t *testing.T) {
	cleanup := enterFreshNetns(t)
	defer cleanup()

	fw := &pod.Firewall{
		Rules: []pod.FirewallRule{
			{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22},
			{Direction: "egress", Protocol: "tcp", PortMin: 443, PortMax: 443, RemoteCIDR: "0.0.0.0/0"},
			{Direction: "egress", Protocol: "udp", PortMin: 53, PortMax: 53},
		},
	}
	if err := ApplyFirewall(fw); err != nil {
		t.Fatalf("ApplyFirewall: %v", err)
	}

	tb, input, output := readFirewallLayout(t)
	c, _ := nft.New(nft.AsLasting())
	defer c.CloseLasting()

	inRules, _ := c.GetRules(tb, input)
	outRules, _ := c.GetRules(tb, output)

	if got, want := len(inRules), 2+1; got != want { // 2 baseline + 1 ingress
		t.Errorf("input rule count = %d, want %d", got, want)
	}
	if got, want := len(outRules), 2; got != want { // 2 egress
		t.Errorf("output rule count = %d, want %d", got, want)
	}
}

func TestApplyFirewall_SecondApplyReplacesPriorState(t *testing.T) {
	cleanup := enterFreshNetns(t)
	defer cleanup()

	first := &pod.Firewall{Rules: []pod.FirewallRule{
		{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22},
		{Direction: "ingress", Protocol: "tcp", PortMin: 80, PortMax: 80},
		{Direction: "ingress", Protocol: "tcp", PortMin: 443, PortMax: 443},
	}}
	if err := ApplyFirewall(first); err != nil {
		t.Fatalf("ApplyFirewall first: %v", err)
	}

	second := &pod.Firewall{Rules: []pod.FirewallRule{
		{Direction: "ingress", Protocol: "udp", PortMin: 5353, PortMax: 5353},
	}}
	if err := ApplyFirewall(second); err != nil {
		t.Fatalf("ApplyFirewall second: %v", err)
	}

	tb, input, _ := readFirewallLayout(t)
	c, _ := nft.New(nft.AsLasting())
	defer c.CloseLasting()
	inRules, _ := c.GetRules(tb, input)
	if got, want := len(inRules), 2+1; got != want {
		t.Errorf("replaced input rule count = %d, want %d (2 baseline + 1 new)", got, want)
	}
}

// readFirewallLayout returns the weft-fw table and its input/output
// chains, or nils if absent. Read with a fresh connection per call
// so a stale netlink socket from a previous apply doesn't bias the
// view.
func readFirewallLayout(t *testing.T) (*nft.Table, *nft.Chain, *nft.Chain) {
	t.Helper()
	c, err := nft.New(nft.AsLasting())
	if err != nil {
		t.Fatalf("nft.New: %v", err)
	}
	defer c.CloseLasting()

	tables, err := c.ListTablesOfFamily(nft.TableFamilyINet)
	if err != nil {
		t.Fatalf("ListTablesOfFamily: %v", err)
	}
	var tb *nft.Table
	for _, t := range tables {
		if t.Name == firewallTableName {
			tb = t
			break
		}
	}
	if tb == nil {
		return nil, nil, nil
	}
	chains, err := c.ListChainsOfTableFamily(nft.TableFamilyINet)
	if err != nil {
		t.Fatalf("ListChainsOfTableFamily: %v", err)
	}
	var input, output *nft.Chain
	for _, ch := range chains {
		if ch.Table == nil || ch.Table.Name != firewallTableName {
			continue
		}
		switch ch.Name {
		case "input":
			input = ch
		case "output":
			output = ch
		}
	}
	return tb, input, output
}
