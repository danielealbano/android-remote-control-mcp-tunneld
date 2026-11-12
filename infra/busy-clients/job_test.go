package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
)

func TestJob_AlertsANewBusyClientOnce(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.store.addLog(t, testNow.Add(-time.Hour), busy("192.0.2.7", 500, 1, testNow.Add(-50*time.Minute))...)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := h.messages.sent()
	if len(sent) != 1 || !strings.Contains(sent[0], "1 new address made") || !strings.Contains(sent[0], ">192.0.2.7</a></td><td>500</td><td>1</td>") {
		t.Fatalf("messages = %q", sent)
	}
	l := h.store.state(t)
	if len(l.Addresses) != 1 || !l.Addresses["192.0.2.7"].Equal(testNow) || h.store.puts != 1 {
		t.Fatalf("state = %+v, puts %d", l, h.store.puts)
	}
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.messages.sent()) != 1 || h.store.puts != 1 {
		t.Fatalf("the second run sent %d messages and saved %d times, want nothing new", len(h.messages.sent())-1, h.store.puts-1)
	}
}

func TestJob_ALaterAlertKeepsEarlierAddresses(t *testing.T) {
	t.Parallel()
	h := newHarness()
	earlier := testNow.Add(-48 * time.Hour)
	h.store.setState(t, alertedList{Addresses: map[string]time.Time{"198.51.100.1": earlier}})
	h.store.addLog(t, testNow.Add(-time.Hour), append(busy("198.51.100.1", 600, 1, testNow.Add(-50*time.Minute)),
		busy("192.0.2.7", 600, 1, testNow.Add(-40*time.Minute))...)...)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := h.messages.sent()
	if len(sent) != 1 || strings.Contains(sent[0], "198.51.100.1") || !strings.Contains(sent[0], "192.0.2.7") {
		t.Fatalf("messages = %q", sent)
	}
	l := h.store.state(t)
	if len(l.Addresses) != 2 || !l.Addresses["198.51.100.1"].Equal(earlier) || !l.Addresses["192.0.2.7"].Equal(testNow) {
		t.Fatalf("state = %+v", l)
	}
}

func TestJob_SortsByConnectionsThenAddress(t *testing.T) {
	t.Parallel()
	h := newHarness()
	var events []store.Event
	for _, b := range []struct {
		ip string
		n  int
	}{{"192.0.2.8", 600}, {"192.0.2.9", 700}, {"192.0.2.10", 600}} {
		events = append(events, busy(b.ip, b.n, 1, testNow.Add(-time.Hour))...)
	}
	h.store.addLog(t, testNow.Add(-2*time.Hour), events...)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := h.messages.sent()
	if len(sent) != 1 {
		t.Fatalf("messages = %q", sent)
	}
	i9, i10, i8 := strings.Index(sent[0], ">192.0.2.9<"), strings.Index(sent[0], ">192.0.2.10<"), strings.Index(sent[0], ">192.0.2.8<")
	if i9 < 0 || i10 < 0 || i8 < 0 || i9 > i10 || i10 > i8 {
		t.Fatalf("rows are not sorted by connections, then address: %s", sent[0])
	}
}

func TestJob_NothingNewSendsNothing(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.dailyHour = 0
	h.store.setState(t, alertedList{Addresses: map[string]time.Time{}, LastDaily: "2026-11-12"})
	h.store.addLog(t, testNow.Add(-time.Hour), busy("192.0.2.7", 499, 1, testNow.Add(-50*time.Minute))...)
	h.store.addLog(t, testNow.Add(-2*time.Hour), busy("192.0.2.8", 99, 5, testNow.Add(-90*time.Minute))...)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.messages.sent()) != 0 || h.store.puts != 0 {
		t.Fatalf("messages %q, puts %d; want none", h.messages.sent(), h.store.puts)
	}
}

func TestJob_AIAndExcludedAddressesAreNeverAlerted(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.ranges = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	h.exclude = []string{"198.51.100.0/24", "203.0.113.5"}
	var events []store.Event
	for _, ip := range []string{"192.0.2.7", "198.51.100.9", "203.0.113.5"} {
		events = append(events, busy(ip, 1000, 5, testNow.Add(-time.Hour))...)
	}
	events = append(events, busy("203.0.113.6", 600, 1, testNow.Add(-time.Hour))...)
	h.store.addLog(t, testNow.Add(-2*time.Hour), events...)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := h.messages.sent()
	if len(sent) != 1 || !strings.Contains(sent[0], ">203.0.113.6<") || strings.Contains(sent[0], "192.0.2.7") ||
		strings.Contains(sent[0], "198.51.100.9") || strings.Contains(sent[0], ">203.0.113.5<") {
		t.Fatalf("messages = %q", sent)
	}
	if l := h.store.state(t); len(l.Addresses) != 1 {
		t.Fatalf("state = %+v", l)
	}
}

func TestJob_ALongAlertGoesOutInNumberedParts(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.rule = rule{connections: 1, spreadConnections: 1, spreadTunnels: 1}
	var events []store.Event
	for i := range 600 {
		events = append(events, publicStart(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), "t1", "", testNow.Add(-time.Hour)))
	}
	h.store.addLog(t, testNow.Add(-2*time.Hour), events...)
	if err := h.job(t).run(context.Background()); err != nil {
		t.Fatal(err)
	}
	sent := h.messages.sent()
	if len(sent) < 2 {
		t.Fatalf("got %d messages, want several parts", len(sent))
	}
	rows := 0
	for i, m := range sent {
		if !strings.HasPrefix(m, fmt.Sprintf("<p>Part %d of %d", i+1, len(sent))) {
			t.Fatalf("message %d starts %.40q", i+1, m)
		}
		if utf8.RuneCountInString(m) > telegram.MessageRunes || strings.Count(m, "<tr>") >= telegram.MessageBlocks {
			t.Fatalf("message %d is over Telegram's limits", i+1)
		}
		rows += strings.Count(m, "<tr><td>")
	}
	if rows != 600 || len(h.pauses) != len(sent)-1 {
		t.Fatalf("rows %d, pauses %d; want 600 rows and a pause between parts", rows, len(h.pauses))
	}
	if l := h.store.state(t); len(l.Addresses) != 600 {
		t.Fatalf("saved %d addresses, want 600", len(l.Addresses))
	}
}

func TestJob_DailyLine(t *testing.T) {
	t.Parallel()
	alerted := map[string]time.Time{"198.51.100.1": testNow.Add(-2 * time.Hour), "198.51.100.2": testNow.Add(-30 * time.Hour)}
	tests := []struct {
		name          string
		now           time.Time
		hour          int
		lastDaily     string
		busy          bool
		wantMessages  []string
		wantLastDaily string
	}{
		{name: "before the hour nothing is sent", hour: 14},
		{
			name: "the first run at the hour sends the line", hour: 13,
			wantMessages:  []string{"<p>The busy-clients check is running (from n1): 1 address alerted in the last 24 hours, 2 on file.</p>"},
			wantLastDaily: "2026-11-12",
		},
		{name: "a later run the same day sends nothing", hour: 13, lastDaily: "2026-11-12", wantLastDaily: "2026-11-12"},
		{
			name: "the next day sends it again", hour: 13, lastDaily: "2026-11-11",
			wantMessages:  []string{"<p>The busy-clients check is running (from n1): 1 address alerted in the last 24 hours, 2 on file.</p>"},
			wantLastDaily: "2026-11-12",
		},
		{
			name: "an alert goes out before the line", hour: 0, busy: true,
			wantMessages:  []string{"<p>Busy clients, from n1: 1 new address", "<p>The busy-clients check is running (from n1): 2 addresses alerted in the last 24 hours, 3 on file.</p>"},
			wantLastDaily: "2026-11-12",
		},
		{
			name: "the day and hour are those of the zone", now: time.Date(2026, 11, 12, 23, 30, 0, 0, time.UTC), hour: 0, lastDaily: "2026-11-12",
			wantMessages:  []string{"<p>The busy-clients check is running (from n1): 1 address alerted in the last 24 hours, 2 on file.</p>"},
			wantLastDaily: "2026-11-13",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			if !tc.now.IsZero() {
				h.now = tc.now
			}
			h.dailyHour = tc.hour
			h.store.setState(t, alertedList{Addresses: maps.Clone(alerted), LastDaily: tc.lastDaily})
			if tc.busy {
				h.store.addLog(t, testNow.Add(-time.Hour), busy("192.0.2.7", 500, 1, testNow.Add(-50*time.Minute))...)
			}
			if err := h.job(t).run(context.Background()); err != nil {
				t.Fatal(err)
			}
			sent := h.messages.sent()
			if len(sent) != len(tc.wantMessages) {
				t.Fatalf("messages = %q, want %d", sent, len(tc.wantMessages))
			}
			for i, want := range tc.wantMessages {
				if !strings.HasPrefix(sent[i], want) {
					t.Fatalf("message %d = %q, want it to start with %q", i+1, sent[i], want)
				}
			}
			if l := h.store.state(t); l.LastDaily != tc.wantLastDaily {
				t.Fatalf("last daily = %q, want %q", l.LastDaily, tc.wantLastDaily)
			}
			if len(tc.wantMessages) == 0 && h.store.puts != 0 {
				t.Fatalf("a run without messages saved %d times", h.store.puts)
			}
		})
	}
}

func TestJob_Failures(t *testing.T) {
	t.Parallel()
	broke := errors.New("broke")
	dailyFails := func(text string) error {
		if strings.Contains(text, "is running") {
			return broke
		}
		return nil
	}
	tests := []struct {
		name          string
		setup         func(h *harness)
		wantErr       string
		wantPuts      int
		wantAddresses int
	}{
		{name: "the alerted list cannot be read", setup: func(h *harness) { h.store.getErr[stateKey] = broke }, wantErr: "read the list of alerted addresses: broke"},
		{name: "the alerted list cannot be decoded", setup: func(h *harness) { h.store.objects[stateKey] = []byte("{") }, wantErr: "decode the list of alerted addresses busy-clients/alerted.json"},
		{name: "the ranges cannot be loaded", setup: func(h *harness) { h.rangesErr = broke }, wantErr: "load the ChatGPT and Claude address ranges: broke"},
		{name: "the logs cannot be listed", setup: func(h *harness) { h.store.listErr = broke }, wantErr: "list the connection logs under"},
		{name: "the alert cannot be sent", setup: func(h *harness) { h.messages.fail = func(string) error { return broke } }, wantErr: "send the alert: message 1 of 1: broke"},
		{name: "the list cannot be saved after the alert", setup: func(h *harness) { h.store.putErr = broke }, wantErr: "the alert was sent but the list of alerted addresses could not be saved, so the next run sends these addresses again: broke"},
		{name: "the daily line cannot be sent", setup: func(h *harness) {
			h.dailyHour = 0
			h.messages.fail = dailyFails
		}, wantErr: "send the daily line: broke", wantPuts: 1, wantAddresses: 1},
		{name: "the daily line cannot be recorded", setup: func(h *harness) {
			h.dailyHour = 0
			h.store.objects = map[string][]byte{}
			h.store.putErr = broke
		}, wantErr: "the daily line was sent but not recorded, so the next run sends it again: broke"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness()
			h.store.addLog(t, testNow.Add(-time.Hour), busy("192.0.2.7", 500, 1, testNow.Add(-50*time.Minute))...)
			tc.setup(h)
			err := h.job(t).run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if h.store.puts != tc.wantPuts {
				t.Fatalf("puts = %d, want %d", h.store.puts, tc.wantPuts)
			}
			if tc.wantPuts > 0 {
				l := h.store.state(t)
				if len(l.Addresses) != tc.wantAddresses || l.LastDaily != "" {
					t.Fatalf("state = %+v", l)
				}
			}
		})
	}
}

func TestJob_ARunOverItsTimeLimitSaysSo(t *testing.T) {
	t.Parallel()
	h := newHarness()
	h.store.getHook = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	h.opts = []jobOption{withTimeout(50 * time.Millisecond)}
	err := h.job(t).run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the run did not finish within 50ms") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewJob_RefusesMissingSettings(t *testing.T) {
	t.Parallel()
	valid := func() jobConfig {
		return jobConfig{
			Store:     newFakeStore(),
			Messages:  &fakeMessenger{},
			Ranges:    func(context.Context) ([]netip.Prefix, error) { return nil, nil },
			Rule:      rule{connections: 500, spreadConnections: 100, spreadTunnels: 3},
			DailyHour: 9,
			Node:      "n1",
			Location:  testZone,
			Logger:    testLogger(&logBuffer{}),
		}
	}
	if _, err := newJob(valid()); err != nil {
		t.Fatalf("a valid configuration is refused: %v", err)
	}
	tests := []struct {
		name   string
		change func(c *jobConfig)
		opts   []jobOption
	}{
		{name: "no store", change: func(c *jobConfig) { c.Store = nil }},
		{name: "no messenger", change: func(c *jobConfig) { c.Messages = nil }},
		{name: "no range loader", change: func(c *jobConfig) { c.Ranges = nil }},
		{name: "a daily hour below 0", change: func(c *jobConfig) { c.DailyHour = -1 }},
		{name: "a daily hour above 23", change: func(c *jobConfig) { c.DailyHour = 24 }},
		{name: "no node", change: func(c *jobConfig) { c.Node = "" }},
		{name: "no time zone", change: func(c *jobConfig) { c.Location = nil }},
		{name: "no logger", change: func(c *jobConfig) { c.Logger = nil }},
		{name: "a rule number that is not positive", change: func(c *jobConfig) { c.Rule.spreadTunnels = 0 }},
		{name: "an empty exclude entry", change: func(c *jobConfig) { c.Exclude = []string{"192.0.2.1", ""} }},
		{name: "an exclude entry that is not an address", change: func(c *jobConfig) { c.Exclude = []string{"example.test"} }},
		{name: "an exclude entry that is not a range", change: func(c *jobConfig) { c.Exclude = []string{"192.0.2.0/33"} }},
		{name: "no clock", change: func(*jobConfig) {}, opts: []jobOption{withClock(nil)}},
		{name: "no sleep function", change: func(*jobConfig) {}, opts: []jobOption{withPause(time.Second, nil)}},
		{name: "a time limit that is not positive", change: func(*jobConfig) {}, opts: []jobOption{withTimeout(0)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := valid()
			tc.change(&c)
			if _, err := newJob(c, tc.opts...); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestParseExclude(t *testing.T) {
	t.Parallel()
	got, err := parseExclude([]string{"203.0.113.5", "198.51.100.9/24", "::ffff:192.0.2.1", "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.5/32", "198.51.100.0/24", "192.0.2.1/32", "2001:db8::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
