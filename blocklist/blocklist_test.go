package blocklist

import "testing"

func TestListMatchesExactAddressesAndCIDRRanges(t *testing.T) {
	list := New([]string{
		"192.0.2.10",
		"198.51.100.0/24",
		"2001:db8::10",
		"2001:db8:1::/48",
		"invalid-entry",
	})

	for _, ip := range []string{"192.0.2.10", "198.51.100.42", "2001:db8::10", "2001:db8:1::42"} {
		if !list.Contains(ip) {
			t.Fatalf("expected %s to be blocked", ip)
		}
	}

	for _, ip := range []string{"192.0.2.11", "203.0.113.10", "2001:db8::11", "not-an-ip"} {
		if list.Contains(ip) {
			t.Fatalf("did not expect %s to be blocked", ip)
		}
	}
}
