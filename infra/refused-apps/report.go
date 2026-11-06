package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

const (
	dateLayout    = "2006-01-02"
	dayLayout     = "Mon 2 Jan 2006"
	timeLayout    = "15:04"
	keyShown      = 12
	retentionDays = 30
)

type newAttempt struct {
	app string
	a   attempt
}

type report struct {
	node       string
	today      time.Time
	lastReport string
	known      map[string]bool
	fresh      []newAttempt
}

func (r report) text() (string, error) {
	loc := r.today.Location()
	var b strings.Builder
	fmt.Fprintf(&b, "Refused apps, report of %s from %s (times in %s).\n", r.today.Format(dayLayout), r.node, loc)
	first := r.lastReport == ""
	if first {
		fmt.Fprintf(&b, "This is the first report, so it lists every refused attempt still on file. Refusal records are deleted after %d days.\n", retentionDays)
	} else {
		last, err := time.ParseInLocation(dateLayout, r.lastReport, loc)
		if err != nil {
			return "", fmt.Errorf("read the date of the last report %q: %w", r.lastReport, err)
		}
		gap := daysBetween(last, r.today)
		if gap > 1 {
			fmt.Fprintf(&b, "The last report was sent on %s; this one also covers the %d %s in between.\n",
				last.Format(dayLayout), gap-1, plural(gap-1, "day", "days"))
		}
		if gap >= retentionDays {
			fmt.Fprintf(&b, "Refusal records are deleted after %d days, so attempts made before %s may be missing.\n",
				retentionDays, r.today.AddDate(0, 0, -retentionDays).Format(dayLayout))
		}
	}
	if len(r.fresh) == 0 {
		b.WriteString("No new attempts.\n")
		return b.String(), nil
	}
	fmt.Fprintf(&b, "%d new %s.\n", len(r.fresh), plural(len(r.fresh), "attempt", "attempts"))
	for _, day := range groupByDay(r.fresh, loc) {
		fmt.Fprintf(&b, "\n%s\n", day.date.Format(dayLayout))
		for _, app := range day.apps {
			name := display(app.name)
			if app.name == "" {
				name = "(no app named in the attestation)"
			}
			if !first && !r.known[app.name] {
				name += " (first time seen)"
			}
			fmt.Fprintf(&b, "%s\n", name)
			for _, v := range app.variants {
				fmt.Fprintf(&b, "  %s\n", v.describe())
				for _, src := range v.sources {
					fmt.Fprintf(&b, "    %s\n", src.describe(loc))
				}
			}
		}
	}
	return b.String(), nil
}

func daysBetween(from, to time.Time) int {
	a := time.Date(from.Year(), from.Month(), from.Day(), 0, 0, 0, 0, time.UTC)
	b := time.Date(to.Year(), to.Month(), to.Day(), 0, 0, 0, 0, time.UTC)
	return int(b.Sub(a).Hours() / 24)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

type dayGroup struct {
	date time.Time
	apps []appGroup
}

type appGroup struct {
	name     string
	variants []variantGroup
}

type variant struct {
	key      string
	version  int64
	verified bool
}

type variantGroup struct {
	variant
	sources []sourceGroup
}

type sourceGroup struct {
	ip    string
	times []time.Time
}

func (v variantGroup) describe() string {
	if v.key == "" && v.version == 0 {
		return "no signing key or version in the attestation, not verified"
	}
	key := "no signing key"
	if v.key != "" {
		key = "key " + display(shorten(v.key, keyShown))
	}
	state := "not verified"
	if v.verified {
		state = "verified"
	}
	return fmt.Sprintf("%s, version %d, %s", key, v.version, state)
}

func (s sourceGroup) describe(loc *time.Location) string {
	first := s.times[0].In(loc).Format(timeLayout)
	if len(s.times) == 1 {
		return fmt.Sprintf("%s: 1 attempt at %s", display(s.ip), first)
	}
	last := s.times[len(s.times)-1].In(loc).Format(timeLayout)
	return fmt.Sprintf("%s: %d attempts, %s to %s", display(s.ip), len(s.times), first, last)
}

func groupByDay(fresh []newAttempt, loc *time.Location) []dayGroup {
	type groupKey struct {
		date string
		app  string
		v    variant
		ip   string
	}
	times := make(map[groupKey][]time.Time)
	dates := make(map[string]time.Time)
	for _, f := range fresh {
		local := f.a.At.In(loc)
		date := local.Format(dateLayout)
		dates[date] = time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
		k := groupKey{date: date, app: f.app, v: variant{key: f.a.Key, version: f.a.Version, verified: f.a.Verified}, ip: f.a.IP}
		times[k] = append(times[k], f.a.At)
	}
	keys := make([]groupKey, 0, len(times))
	for k := range times {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		switch {
		case a.date != b.date:
			return a.date < b.date
		case a.app != b.app:
			return a.app < b.app
		case a.v.key != b.v.key:
			return a.v.key < b.v.key
		case a.v.version != b.v.version:
			return a.v.version < b.v.version
		case a.v.verified != b.v.verified:
			return b.v.verified
		default:
			return a.ip < b.ip
		}
	})
	var days []dayGroup
	for _, k := range keys {
		ts := times[k]
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		if len(days) == 0 || !days[len(days)-1].date.Equal(dates[k.date]) {
			days = append(days, dayGroup{date: dates[k.date]})
		}
		day := &days[len(days)-1]
		if len(day.apps) == 0 || day.apps[len(day.apps)-1].name != k.app {
			day.apps = append(day.apps, appGroup{name: k.app})
		}
		app := &day.apps[len(day.apps)-1]
		if len(app.variants) == 0 || app.variants[len(app.variants)-1].variant != k.v {
			app.variants = append(app.variants, variantGroup{variant: k.v})
		}
		v := &app.variants[len(app.variants)-1]
		v.sources = append(v.sources, sourceGroup{ip: k.ip, times: ts})
	}
	return days
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func display(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '\uFFFD'
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}

func splitMessage(text string, limit int) []string {
	var parts []string
	var cur strings.Builder
	curLen := 0
	flush := func() {
		if s := strings.Trim(cur.String(), "\n"); s != "" {
			parts = append(parts, s)
		}
		cur.Reset()
		curLen = 0
	}
	for _, line := range strings.SplitAfter(text, "\n") {
		for _, piece := range splitLine(line, limit) {
			n := utf16Len(piece)
			if curLen+n > limit {
				flush()
			}
			cur.WriteString(piece)
			curLen += n
		}
	}
	flush()
	return parts
}

func splitLine(line string, limit int) []string {
	if utf16Len(line) <= limit {
		return []string{line}
	}
	var pieces []string
	start, n := 0, 0
	for i, r := range line {
		w := utf16.RuneLen(r)
		if n+w > limit {
			pieces = append(pieces, line[start:i])
			start, n = i, 0
		}
		n += w
	}
	return append(pieces, line[start:])
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}
