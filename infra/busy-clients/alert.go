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
	node   string
	now    time.Time
	fresh  []*usage
	places []place
}

func (r alert) messages(lim telegram.Limits) ([]string, []int) {
	loc := r.now.Location()
	n := len(r.fresh)
	lead := []string{fmt.Sprintf("%d new busy %s on %s in the last 24 hours (times in %s).", n, plural(n, "client", "clients"), r.node, loc)}
	rows := make([][]telegram.Cell, n)
	for i, u := range r.fresh {
		rows[i] = []telegram.Cell{
			{Text: u.address, URL: lookupURL + u.lookup.String()},
			telegram.Text(r.places[i].country),
			telegram.Text(r.places[i].network),
			telegram.Text(strconv.Itoa(u.connections)),
			telegram.Text(strconv.Itoa(len(u.tunnels))),
			telegram.Text(u.first.In(loc).Format(dayTimeLayout)),
			telegram.Text(u.last.In(loc).Format(dayTimeLayout)),
			telegram.Text(strconv.Itoa(len(u.fingerprints))),
		}
	}
	return telegram.PackRows(lead, []telegram.Section{{
		Columns: []string{"Address", "Country", "Network", "Connections", "Tunnels", "First", "Last", "TLS fingerprints"},
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
