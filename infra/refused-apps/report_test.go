package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
)

var testZone = time.FixedZone("TEST", 3600)

func at(day, hour, minute int) time.Time {
	return time.Date(2026, 11, day, hour, minute, 0, 0, testZone).UTC()
}

var testToday = time.Date(2026, 11, 7, 11, 0, 0, 0, testZone)

func sampleReport() report {
	return report{
		node:       "n1",
		today:      testToday,
		lastReport: "2026-11-06",
		known:      map[string]bool{"dev.example.known": true},
		fresh: []newAttempt{
			{app: "dev.example.copy", a: attempt{At: at(6, 23, 29), IP: "198.51.100.7", Key: "6954770e320b058518c3dc3a", Version: 20011750, Verified: true}},
			{app: "dev.example.copy", a: attempt{At: at(6, 21, 15), IP: "198.51.100.7", Key: "6954770e320b058518c3dc3a", Version: 20011750, Verified: true}},
			{app: "dev.example.known", a: attempt{At: at(7, 9, 0), IP: "203.0.113.9", Key: "aa", Version: 3}},
			{app: "dev.example.copy", a: attempt{At: at(7, 8, 30), IP: "203.0.113.4", Key: "6954770e320b058518c3dc3a", Version: 20011750, Verified: true}},
		},
	}
}

func TestReport_Intro(t *testing.T) {
	t.Parallel()
	one := []newAttempt{{app: "dev.example.copy", a: attempt{At: at(6, 21, 15), IP: "198.51.100.7"}}}
	tests := []struct {
		name       string
		lastReport string
		fresh      []newAttempt
		want       []string
	}{
		{
			name:       "a quiet day says there is nothing new",
			lastReport: "2026-11-06",
			want:       []string{"Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).", "No new attempts."},
		},
		{
			name:  "the first report says it lists everything on file",
			fresh: one,
			want: []string{
				"Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).",
				"This is the first report, so it lists every refused attempt still on file. Refusal records are deleted after 30 days.",
				"1 new attempt.",
			},
		},
		{
			name:       "missed days are named",
			lastReport: "2026-11-03",
			fresh:      append(one, one...),
			want: []string{
				"Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).",
				"The last report was sent on Tue 3 Nov 2026; this one also covers the 3 days in between.",
				"2 new attempts.",
			},
		},
		{
			name:       "a single missed day reads as one day",
			lastReport: "2026-11-05",
			want: []string{
				"Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).",
				"The last report was sent on Thu 5 Nov 2026; this one also covers the 1 day in between.",
				"No new attempts.",
			},
		},
		{
			name:       "a gap beyond the retention warns that attempts may be missing",
			lastReport: "2026-10-01",
			want: []string{
				"Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).",
				"The last report was sent on Thu 1 Oct 2026; this one also covers the 36 days in between.",
				"Refusal records are deleted after 30 days, so attempts made before Thu 8 Oct 2026 may be missing.",
				"No new attempts.",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := report{node: "n1", today: testToday, lastReport: tc.lastReport, fresh: tc.fresh}.intro()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("intro = %q\nwant    %q", got, tc.want)
			}
		})
	}
}

func TestReport_IntroRefusesAnUnreadableLastReport(t *testing.T) {
	t.Parallel()
	if _, err := (report{node: "n1", today: testToday, lastReport: "yesterday"}).messages(telegram.Limits{Blocks: 500, Runes: 32768}); err == nil {
		t.Fatal("an unreadable last report date must fail")
	}
}

func TestReport_ByApp(t *testing.T) {
	t.Parallel()
	r := sampleReport()
	got := r.byApp(groupByDay(r.fresh, testZone))
	want := []telegram.Section{
		{
			Heading: "dev.example.copy (first time seen)", Note: "key 6954770e320b…, version 20011750, verified",
			Columns: []string{"Day", "Time", "IP", "Tries"},
			Rows: [][]telegram.Cell{
				{telegram.Text("Fri 6 Nov"), telegram.Text("21:15–23:29"), telegram.Text("198.51.100.7"), telegram.Text("2")},
				{telegram.Text("Sat 7 Nov"), telegram.Text("08:30"), telegram.Text("203.0.113.4"), telegram.Text("1")},
			},
		},
		{
			Heading: "dev.example.known", Note: "key aa, version 3, not verified",
			Columns: []string{"Day", "Time", "IP", "Tries"},
			Rows:    [][]telegram.Cell{{telegram.Text("Sat 7 Nov"), telegram.Text("09:00"), telegram.Text("203.0.113.9"), telegram.Text("1")}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sections = %+v\nwant       %+v", got, want)
	}
}

func TestReport_AppNames(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", cellRunes+10)
	tests := []struct {
		name       string
		lastReport string
		known      map[string]bool
		app        string
		want       string
	}{
		{name: "the first report marks nothing as first seen", app: "dev.example.copy", want: "dev.example.copy"},
		{name: "a known app is not marked", lastReport: "2026-11-06", known: map[string]bool{"dev.example.copy": true}, app: "dev.example.copy", want: "dev.example.copy"},
		{name: "an attestation without an app says so", lastReport: "2026-11-06", app: "", want: "(no app named in the attestation) (first time seen)"},
		{name: "control and direction characters are replaced", lastReport: "2026-11-06", app: "dev.example\n\u202ecopy", want: "dev.example\uFFFD\uFFFDcopy (first time seen)"},
		{name: "a long name is cut but keeps its mark", lastReport: "2026-11-06", app: long, want: long[:cellRunes] + "… (first time seen)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := report{today: testToday, lastReport: tc.lastReport, known: tc.known}
			if got := r.appName(tc.app); got != tc.want {
				t.Fatalf("appName(%q) = %q, want %q", tc.app, got, tc.want)
			}
		})
	}
}

func TestVariant_Texts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		v            variant
		wantDescribe string
		wantKey      string
	}{
		{name: "a verified key", v: variant{key: "6954770e320b058518c3dc3a", version: 20011750, verified: true}, wantDescribe: "key 6954770e320b…, version 20011750, verified", wantKey: "6954770e320b…"},
		{name: "no key", v: variant{version: 1}, wantDescribe: "no signing key, version 1, not verified", wantKey: "none"},
		{name: "neither key nor version", v: variant{}, wantDescribe: "no signing key or version in the attestation, not verified", wantKey: "none"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.v.describe(); got != tc.wantDescribe {
				t.Errorf("describe = %q, want %q", got, tc.wantDescribe)
			}
			if got := tc.v.keyText(); got != tc.wantKey {
				t.Errorf("keyText = %q, want %q", got, tc.wantKey)
			}
		})
	}
}

func TestReport_MessagesHaveOneTablePerAppAndKey(t *testing.T) {
	t.Parallel()
	msgs, err := sampleReport().messages(telegram.Limits{Blocks: 500, Runes: 32768})
	if err != nil {
		t.Fatal(err)
	}
	want := "<p>Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).<br>4 new attempts.</p>" +
		"<h4>dev.example.copy (first time seen)</h4><p>key 6954770e320b…, version 20011750, verified</p>" + "<table bordered striped compact>" +
		"<tr><th>Day</th><th>Time</th><th>IP</th><th>Tries</th></tr>" +
		"<tr><td>Fri 6 Nov</td><td>21:15–23:29</td><td>198.51.100.7</td><td>2</td></tr>" +
		"<tr><td>Sat 7 Nov</td><td>08:30</td><td>203.0.113.4</td><td>1</td></tr>" + "</table>" +
		"<h4>dev.example.known</h4><p>key aa, version 3, not verified</p>" + "<table bordered striped compact>" +
		"<tr><th>Day</th><th>Time</th><th>IP</th><th>Tries</th></tr>" +
		"<tr><td>Sat 7 Nov</td><td>09:00</td><td>203.0.113.9</td><td>1</td></tr>" + "</table>"
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}
