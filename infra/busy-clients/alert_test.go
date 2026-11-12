package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
)

const tableHead = "<h4>New busy clients</h4><table bordered striped compact><tr><th>Address</th><th>Connections</th><th>Tunnels</th>" +
	"<th>First</th><th>Last</th><th>TLS fingerprints</th></tr>"

const ruleLines = "An address is flagged at 500 or more connections, or 100 or more to at least 3 tunnels. " +
	"ChatGPT and Claude addresses are left out, and each address is reported only once.<br>" +
	"To block an address, add it to the ban file. To stop reports of other addresses of the same network, add its range to the exclude list."

func TestAlert_Messages(t *testing.T) {
	t.Parallel()
	v4 := usageWith(600, 1)
	v4.address, v4.lookup = "192.0.2.7", netip.MustParseAddr("192.0.2.7")
	v4.fingerprints = map[string]struct{}{"a": {}, "b": {}}
	v4.first, v4.last = time.Date(2026, 11, 11, 13, 0, 0, 0, time.UTC), time.Date(2026, 11, 12, 11, 30, 0, 0, time.UTC)
	v6 := usageWith(120, 3)
	v6.address, v6.lookup = "2001:db8:1:2::/64", netip.MustParseAddr("2001:db8:1:2::5")
	v6.fingerprints = map[string]struct{}{"a": {}}
	v6.first, v6.last = time.Date(2026, 11, 12, 9, 5, 0, 0, time.UTC), time.Date(2026, 11, 12, 9, 6, 0, 0, time.UTC)
	r := rule{connections: 500, spreadConnections: 100, spreadTunnels: 3}
	lim := telegram.Limits{Blocks: telegram.MessageBlocks, Runes: telegram.MessageRunes}
	tests := []struct {
		name  string
		fresh []*usage
		want  string
	}{
		{
			name:  "two addresses",
			fresh: []*usage{v4, v6},
			want: "<p>Busy clients, from n1: 2 new addresses made unusually many tunnel connections in the 24 hours up to Thu 12 Nov 13:00 (times in TEST).<br>" +
				ruleLines + "</p>" + tableHead +
				`<tr><td><a href="https://ipinfo.io/192.0.2.7">192.0.2.7</a></td><td>600</td><td>1</td><td>Wed 11 Nov 14:00</td><td>Thu 12 Nov 12:30</td><td>2</td></tr>` +
				`<tr><td><a href="https://ipinfo.io/2001:db8:1:2::5">2001:db8:1:2::/64</a></td><td>120</td><td>3</td><td>Thu 12 Nov 10:05</td><td>Thu 12 Nov 10:06</td><td>1</td></tr>` +
				"</table>",
		},
		{
			name:  "one address",
			fresh: []*usage{v4},
			want: "<p>Busy clients, from n1: 1 new address made unusually many tunnel connections in the 24 hours up to Thu 12 Nov 13:00 (times in TEST).<br>" +
				ruleLines + "</p>" + tableHead +
				`<tr><td><a href="https://ipinfo.io/192.0.2.7">192.0.2.7</a></td><td>600</td><td>1</td><td>Wed 11 Nov 14:00</td><td>Thu 12 Nov 12:30</td><td>2</td></tr>` +
				"</table>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := alert{node: "n1", now: testNow.In(testZone), rule: r, fresh: tc.fresh}.messages(lim)
			if len(msgs) != 1 || msgs[0] != tc.want {
				t.Fatalf("messages = %q\nwant       %q", msgs, tc.want)
			}
		})
	}
}

func TestDailyLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		node            string
		alerted, onFile int
		want            string
	}{
		{node: "n1", alerted: 1, onFile: 3, want: "<p>The busy-clients check is running (from n1): 1 address alerted in the last 24 hours, 3 on file.</p>"},
		{node: "n1", alerted: 0, onFile: 0, want: "<p>The busy-clients check is running (from n1): 0 addresses alerted in the last 24 hours, 0 on file.</p>"},
		{node: "<n&1>", alerted: 2, onFile: 2, want: "<p>The busy-clients check is running (from &lt;n&amp;1&gt;): 2 addresses alerted in the last 24 hours, 2 on file.</p>"},
	}
	for _, tc := range tests {
		if got := dailyLine(tc.node, tc.alerted, tc.onFile); got != tc.want {
			t.Errorf("dailyLine(%q, %d, %d) = %q, want %q", tc.node, tc.alerted, tc.onFile, got, tc.want)
		}
	}
}
