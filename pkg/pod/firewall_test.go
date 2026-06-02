package pod

import "testing"

func TestFirewallRule_Validate(t *testing.T) {
	cases := []struct {
		name    string
		r       FirewallRule
		wantErr bool
	}{
		{"allow ingress tcp 22 from any", FirewallRule{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22}, false},
		{"allow ingress tcp 80-443 from /24", FirewallRule{Direction: "ingress", Protocol: "tcp", PortMin: 80, PortMax: 443, RemoteCIDR: "10.0.0.0/24"}, false},
		{"allow egress any", FirewallRule{Direction: "egress"}, false},
		{"allow icmp any", FirewallRule{Direction: "ingress", Protocol: "icmp"}, false},
		{"ipv6 cidr ok", FirewallRule{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22, RemoteCIDR: "2001:db8::/32"}, false},

		{"unknown direction", FirewallRule{Direction: "in", Protocol: "tcp", PortMin: 22, PortMax: 22}, true},
		{"unknown protocol", FirewallRule{Direction: "ingress", Protocol: "sctp"}, true},
		{"port range without tcp/udp", FirewallRule{Direction: "ingress", Protocol: "icmp", PortMin: 1, PortMax: 1}, true},
		{"port_min > port_max", FirewallRule{Direction: "ingress", Protocol: "tcp", PortMin: 443, PortMax: 80}, true},
		{"bad cidr", FirewallRule{Direction: "ingress", Protocol: "tcp", PortMin: 80, PortMax: 80, RemoteCIDR: "not-a-cidr"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.r.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestFirewall_ValidateAggregatesIndex(t *testing.T) {
	f := Firewall{Rules: []FirewallRule{
		{Direction: "ingress", Protocol: "tcp", PortMin: 22, PortMax: 22},
		{Direction: "bogus"},
	}}
	err := f.Validate()
	if err == nil {
		t.Fatal("expected error on second rule")
	}
	if got := err.Error(); !contains(got, "rule[1]") {
		t.Errorf("error %q should mention rule[1]", got)
	}
}

func TestFirewall_EmptyIsValid(t *testing.T) {
	if err := (&Firewall{}).Validate(); err != nil {
		t.Errorf("empty firewall should validate: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
