package main

import (
	"fmt"
	"html"
	"strconv"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
)

const (
	dayTimeLayout = "Mon 2 Jan 15:04"
	lookupURL     = "https://ipinfo.io/"
)

type alert struct {
	node  string
	now   time.Time
	rule  rule
	fresh []*usage
}

func (r alert) messages(lim telegram.Limits) ([]string, []int) {
	loc := r.now.Location()
	n := len(r.fresh)
	lead := []string{
		fmt.Sprintf("Busy clients, from %s: %d new %s made unusually many tunnel connections in the 24 hours up to %s (times in %s).",
			r.node, n, plural(n, "address", "addresses"), r.now.Format(dayTimeLayout), loc),
		fmt.Sprintf("An address is flagged at %s. ChatGPT and Claude addresses are left out, and each address is reported only once.", r.rule.describe()),
		"To block an address, add it to the ban file. To stop reports of other addresses of the same network, add its range to the exclude list.",
	}
	rows := make([][]telegram.Cell, n)
	for i, u := range r.fresh {
		rows[i] = []telegram.Cell{
			{Text: u.address, URL: lookupURL + u.lookup.String()},
			telegram.Text(strconv.Itoa(u.connections)),
			telegram.Text(strconv.Itoa(len(u.tunnels))),
			telegram.Text(u.first.In(loc).Format(dayTimeLayout)),
			telegram.Text(u.last.In(loc).Format(dayTimeLayout)),
			telegram.Text(strconv.Itoa(len(u.fingerprints))),
		}
	}
	return telegram.PackRows(lead, []telegram.Section{{
		Heading: "New busy clients",
		Columns: []string{"Address", "Connections", "Tunnels", "First", "Last", "TLS fingerprints"},
		Rows:    rows,
	}}, lim)
}

func dailyLine(node string, alerted, onFile int) string {
	return "<p>" + html.EscapeString(fmt.Sprintf("The busy-clients check is running (from %s): %d %s alerted in the last 24 hours, %d on file.",
		node, alerted, plural(alerted, "address", "addresses"), onFile)) + "</p>"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
