package main

import (
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

var testZone = time.FixedZone("TEST", 3600)

func at(day, hour, minute int) time.Time {
	return time.Date(2026, 11, day, hour, minute, 0, 0, testZone).UTC()
}

func TestReport_Text(t *testing.T) {
	today := time.Date(2026, 11, 7, 11, 0, 0, 0, testZone)
	copyApp := attempt{At: at(6, 21, 15), IP: "198.51.100.7", Key: "6954770e320b058518c3dc3a", Version: 20011750, Verified: true}
	tests := []struct {
		name       string
		lastReport string
		known      map[string]bool
		fresh      []newAttempt
		want       []string
		wantNot    []string
	}{
		{
			name:       "a quiet day says there is nothing new",
			lastReport: "2026-11-06",
			want:       []string{"Refused apps, report of Sat 7 Nov 2026 from n1 (times in TEST).", "No new attempts."},
			wantNot:    []string{"covers", "may be missing"},
		},
		{
			name:    "the first report says it lists everything on file and marks nothing as first seen",
			fresh:   []newAttempt{{app: "dev.example.copy", a: copyApp}},
			want:    []string{"This is the first report", "deleted after 30 days", "1 new attempt."},
			wantNot: []string{"(first time seen)"},
		},
		{
			name:       "an app never seen before is marked, a known one is not",
			lastReport: "2026-11-06",
			known:      map[string]bool{"dev.example.known": true},
			fresh: []newAttempt{
				{app: "dev.example.copy", a: copyApp},
				{app: "dev.example.known", a: attempt{At: at(7, 9, 0), IP: "203.0.113.9", Key: "aa", Version: 3}},
			},
			want: []string{
				"2 new attempts.",
				"\nFri 6 Nov 2026\ndev.example.copy (first time seen)\n  key 6954770e320b…, version 20011750, verified\n    198.51.100.7: 1 attempt at 21:15\n",
				"\nSat 7 Nov 2026\ndev.example.known\n  key aa, version 3, not verified\n    203.0.113.9: 1 attempt at 09:00\n",
			},
			wantNot: []string{"dev.example.known (first time seen)"},
		},
		{
			name:       "several attempts from one address are counted with their first and last time",
			lastReport: "2026-11-06",
			known:      map[string]bool{"dev.example.copy": true},
			fresh: []newAttempt{
				{app: "dev.example.copy", a: attempt{At: at(6, 23, 29), IP: "198.51.100.7", Key: "aa", Version: 1}},
				{app: "dev.example.copy", a: attempt{At: at(6, 21, 15), IP: "198.51.100.7", Key: "aa", Version: 1}},
				{app: "dev.example.copy", a: attempt{At: at(6, 22, 0), IP: "198.51.100.7", Key: "aa", Version: 1}},
			},
			want: []string{"    198.51.100.7: 3 attempts, 21:15 to 23:29\n"},
		},
		{
			name:       "missed days are named",
			lastReport: "2026-11-03",
			want:       []string{"The last report was sent on Tue 3 Nov 2026; this one also covers the 3 days in between."},
			wantNot:    []string{"may be missing"},
		},
		{
			name:       "a single missed day reads as one day",
			lastReport: "2026-11-05",
			want:       []string{"this one also covers the 1 day in between."},
		},
		{
			name:       "a gap beyond the retention warns that attempts may be missing",
			lastReport: "2026-10-01",
			want:       []string{"covers the 36 days in between.", "attempts made before Thu 8 Oct 2026 may be missing."},
		},
		{
			name:       "an app name cannot add lines to the message",
			lastReport: "2026-11-06",
			known:      map[string]bool{},
			fresh:      []newAttempt{{app: "dev.example.copy\n  key fake, verified\u202e", a: copyApp}},
			want:       []string{"dev.example.copy\uFFFD  key fake, verified\uFFFD (first time seen)\n"},
		},
		{
			name:       "an attestation without an app or key says so",
			lastReport: "2026-11-06",
			known:      map[string]bool{},
			fresh:      []newAttempt{{app: "", a: attempt{At: at(6, 21, 15), IP: "198.51.100.7"}}},
			want:       []string{"(no app named in the attestation) (first time seen)\n  no signing key or version in the attestation, not verified\n"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := report{node: "n1", today: today, lastReport: tc.lastReport, known: tc.known, fresh: tc.fresh}.text()
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("report lacks %q:\n%s", w, got)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(got, w) {
					t.Errorf("report has %q:\n%s", w, got)
				}
			}
		})
	}
}

func TestReport_TextRefusesAnUnreadableLastReport(t *testing.T) {
	t.Parallel()
	if _, err := (report{node: "n1", today: time.Now(), lastReport: "yesterday"}).text(); err == nil {
		t.Fatal("an unreadable last report date must fail")
	}
}

func TestSplitMessage(t *testing.T) {
	t.Parallel()
	line := strings.Repeat("a", 30) + "\n"
	tests := []struct {
		name      string
		text      string
		limit     int
		wantParts int
	}{
		{name: "a short text is one part", text: "hello\nworld\n", limit: 100, wantParts: 1},
		{name: "a long text splits between lines", text: strings.Repeat(line, 10), limit: 100, wantParts: 4},
		{name: "a line longer than the limit is cut", text: strings.Repeat("b", 250), limit: 100, wantParts: 3},
		{name: "characters outside the basic plane count twice", text: strings.Repeat("\U0001F600", 60), limit: 100, wantParts: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parts := splitMessage(tc.text, tc.limit)
			if len(parts) != tc.wantParts {
				t.Fatalf("got %d parts, want %d: %q", len(parts), tc.wantParts, parts)
			}
			joined := strings.Join(parts, "")
			if strings.ReplaceAll(joined, "\n", "") != strings.ReplaceAll(tc.text, "\n", "") {
				t.Fatal("splitting lost or changed text")
			}
			for _, p := range parts {
				if n := len(utf16.Encode([]rune(p))); n > tc.limit || n == 0 {
					t.Fatalf("part of %d UTF-16 units, limit %d", n, tc.limit)
				}
			}
		})
	}
}
