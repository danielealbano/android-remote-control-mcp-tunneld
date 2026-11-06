package main

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
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
	if _, err := (report{node: "n1", today: testToday, lastReport: "yesterday"}).messages(messageLimits{blocks: 500, runes: 32768}); err == nil {
		t.Fatal("an unreadable last report date must fail")
	}
}

func TestReport_ByApp(t *testing.T) {
	t.Parallel()
	r := sampleReport()
	got := r.byApp(groupByDay(r.fresh, testZone))
	want := []section{
		{
			heading: "dev.example.copy (first time seen)", note: "key 6954770e320b…, version 20011750, verified",
			columns: []string{"Day", "Time", "IP", "Tries"},
			rows: [][]string{
				{"Fri 6 Nov", "21:15–23:29", "198.51.100.7", "2"},
				{"Sat 7 Nov", "08:30", "203.0.113.4", "1"},
			},
		},
		{
			heading: "dev.example.known", note: "key aa, version 3, not verified",
			columns: []string{"Day", "Time", "IP", "Tries"},
			rows:    [][]string{{"Sat 7 Nov", "09:00", "203.0.113.9", "1"}},
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
	msgs, err := sampleReport().messages(messageLimits{blocks: 500, runes: 32768})
	if err != nil {
		t.Fatal(err)
	}
	want := "<p>Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).<br>4 new attempts.</p>" +
		"<h4>dev.example.copy (first time seen)</h4><p>key 6954770e320b…, version 20011750, verified</p>" + tableStart +
		"<tr><th>Day</th><th>Time</th><th>IP</th><th>Tries</th></tr>" +
		"<tr><td>Fri 6 Nov</td><td>21:15–23:29</td><td>198.51.100.7</td><td>2</td></tr>" +
		"<tr><td>Sat 7 Nov</td><td>08:30</td><td>203.0.113.4</td><td>1</td></tr>" + tableEnd +
		"<h4>dev.example.known</h4><p>key aa, version 3, not verified</p>" + tableStart +
		"<tr><th>Day</th><th>Time</th><th>IP</th><th>Tries</th></tr>" +
		"<tr><td>Sat 7 Nov</td><td>09:00</td><td>203.0.113.9</td><td>1</td></tr>" + tableEnd
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}

func testSection(name string, rows int) section {
	s := section{heading: name, note: "note", columns: []string{"A", "B"}}
	for i := range rows {
		s.rows = append(s.rows, []string{name, "row" + strconv.Itoa(i)})
	}
	return s
}

func TestPack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sections []section
		lim      messageLimits
		want     int
	}{
		{name: "a report without attempts is the intro alone", lim: messageLimits{blocks: 500, runes: 32768}, want: 1},
		{name: "everything that fits is one message", sections: []section{testSection("x", 3), testSection("y", 3)}, lim: messageLimits{blocks: 500, runes: 32768}, want: 1},
		{name: "too many rows split by blocks", sections: []section{testSection("x", 30)}, lim: messageLimits{blocks: 15, runes: 32768}, want: 3},
		{name: "too much text splits by characters", sections: []section{testSection("x", 30)}, lim: messageLimits{blocks: 500, runes: 600}, want: 3},
		{name: "a section that no longer fits starts the next message", sections: []section{testSection("x", 8), testSection("y", 8)}, lim: messageLimits{blocks: 15, runes: 32768}, want: 2},
		{name: "a row larger than a message still goes out alone", sections: []section{testSection("x", 2)}, lim: messageLimits{blocks: 500, runes: 10}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := pack([]string{"intro"}, tc.sections, tc.lim)
			if len(msgs) != tc.want {
				t.Fatalf("got %d messages, want %d: %q", len(msgs), tc.want, msgs)
			}
			rows := map[string]int{}
			for i, m := range msgs {
				lead := "<p>intro</p>"
				if len(msgs) > 1 {
					lead = "<p>Part " + strconv.Itoa(i+1) + " of " + strconv.Itoa(len(msgs))
				}
				if !strings.HasPrefix(m, lead) {
					t.Fatalf("message %d starts %.40q, want %q", i+1, m, lead)
				}
				if i > 0 && strings.Contains(m, "intro") {
					t.Fatalf("message %d repeats the intro", i+1)
				}
				if tc.lim.runes > 100 && (utf8.RuneCountInString(m) > tc.lim.runes || strings.Count(m, "<tr>")+strings.Count(m, "<h4>")+strings.Count(m, "<p>")+strings.Count(m, "<table") > tc.lim.blocks) {
					t.Fatalf("message %d is over the limits %+v: %s", i+1, tc.lim, m)
				}
				for _, s := range tc.sections {
					if strings.Contains(m, "<td>"+s.heading+"</td>") && !strings.Contains(m, "<h4>"+s.heading+"</h4><p>note</p>"+tableStart+"<tr><th>A</th><th>B</th></tr>") {
						t.Fatalf("message %d has rows of %s without its heading and table header", i+1, s.heading)
					}
					for j := range s.rows {
						rows[s.heading+"/"+strconv.Itoa(j)] += strings.Count(m, "<td>"+s.heading+"</td><td>row"+strconv.Itoa(j)+"</td>")
					}
				}
			}
			for _, s := range tc.sections {
				for j := range s.rows {
					if n := rows[s.heading+"/"+strconv.Itoa(j)]; n != 1 {
						t.Fatalf("row %d of %s appears %d times", j, s.heading, n)
					}
				}
			}
		})
	}
}

func TestPack_EscapesEveryValue(t *testing.T) {
	t.Parallel()
	s := section{heading: "<b>h</b>", note: "a & b", columns: []string{"<th>"}, rows: [][]string{{"</td><script>"}}}
	msgs := pack([]string{"<i>intro</i>"}, []section{s}, messageLimits{blocks: 500, runes: 32768})
	want := "<p>&lt;i&gt;intro&lt;/i&gt;</p><h4>&lt;b&gt;h&lt;/b&gt;</h4><p>a &amp; b</p>" + tableStart +
		"<tr><th>&lt;th&gt;</th></tr><tr><td>&lt;/td&gt;&lt;script&gt;</td></tr>" + tableEnd
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}
