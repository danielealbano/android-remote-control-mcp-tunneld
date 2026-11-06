package main

import (
	"fmt"
	"html"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	dateLayout     = "2006-01-02"
	dayLayout      = "Mon 2 Jan 2006"
	shortDayLayout = "Mon 2 Jan"
	timeLayout     = "15:04"
	keyShown       = 12
	retentionDays  = 30
	cellRunes      = 256
	partRoom       = 32
	tableStart     = "<table bordered striped compact>"
	tableEnd       = "</table>"
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

type section struct {
	heading string
	note    string
	columns []string
	rows    [][]string
}

type messageLimits struct {
	blocks int
	runes  int
}

func (r report) messages(lim messageLimits) ([]string, error) {
	intro, err := r.intro()
	if err != nil {
		return nil, err
	}
	return pack(intro, r.byApp(groupByDay(r.fresh, r.today.Location())), lim), nil
}

func (r report) intro() ([]string, error) {
	loc := r.today.Location()
	lines := []string{fmt.Sprintf("Refused apps, report of %s from %s (times in %s).", r.today.Format(dayLayout), r.node, loc)}
	if r.first() {
		lines = append(lines, fmt.Sprintf("This is the first report, so it lists every refused attempt still on file. Refusal records are deleted after %d days.", retentionDays))
	} else {
		last, err := time.ParseInLocation(dateLayout, r.lastReport, loc)
		if err != nil {
			return nil, fmt.Errorf("read the date of the last report %q: %w", r.lastReport, err)
		}
		gap := daysBetween(last, r.today)
		if gap > 1 {
			lines = append(lines, fmt.Sprintf("The last report was sent on %s; this one also covers the %d %s in between.",
				last.Format(dayLayout), gap-1, plural(gap-1, "day", "days")))
		}
		if gap >= retentionDays {
			lines = append(lines, fmt.Sprintf("Refusal records are deleted after %d days, so attempts made before %s may be missing.",
				retentionDays, r.today.AddDate(0, 0, -retentionDays).Format(dayLayout)))
		}
	}
	if len(r.fresh) == 0 {
		return append(lines, "No new attempts."), nil
	}
	return append(lines, fmt.Sprintf("%d new %s.", len(r.fresh), plural(len(r.fresh), "attempt", "attempts"))), nil
}

func (r report) first() bool {
	return r.lastReport == ""
}

func (r report) appName(name string) string {
	s := clip(display(name), cellRunes)
	if name == "" {
		s = "(no app named in the attestation)"
	}
	if !r.first() && !r.known[name] {
		s += " (first time seen)"
	}
	return s
}

func (r report) byApp(days []dayGroup) []section {
	type appVariant struct {
		app string
		v   variant
	}
	loc := r.today.Location()
	index := make(map[appVariant]int)
	var sections []section
	for _, day := range days {
		for _, app := range day.apps {
			for _, v := range app.variants {
				k := appVariant{app: app.name, v: v.variant}
				i, ok := index[k]
				if !ok {
					i = len(sections)
					index[k] = i
					sections = append(sections, section{heading: r.appName(app.name), note: v.describe(), columns: []string{"Day", "Time", "IP", "Tries"}})
				}
				for _, src := range v.sources {
					sections[i].rows = append(sections[i].rows, []string{
						day.date.Format(shortDayLayout), src.span(loc), clip(display(src.ip), cellRunes), strconv.Itoa(len(src.times)),
					})
				}
			}
		}
	}
	return sections
}

func (s section) render() (head string, blocks int, rows []string) {
	var b strings.Builder
	b.WriteString("<h4>" + html.EscapeString(s.heading) + "</h4>")
	blocks = 3
	if s.note != "" {
		b.WriteString("<p>" + html.EscapeString(s.note) + "</p>")
		blocks++
	}
	b.WriteString(tableStart + "<tr>")
	for _, c := range s.columns {
		b.WriteString("<th>" + html.EscapeString(c) + "</th>")
	}
	b.WriteString("</tr>")
	rows = make([]string, len(s.rows))
	for i, row := range s.rows {
		var rb strings.Builder
		rb.WriteString("<tr>")
		for _, c := range row {
			rb.WriteString("<td>" + html.EscapeString(c) + "</td>")
		}
		rb.WriteString("</tr>")
		rows[i] = rb.String()
	}
	return b.String(), blocks, rows
}

func pack(lead []string, sections []section, lim messageLimits) []string {
	escaped := make([]string, len(lead))
	for i, l := range lead {
		escaped[i] = html.EscapeString(l)
	}
	intro := strings.Join(escaped, "<br>")
	var bodies []string
	var cur strings.Builder
	var blocks, runes, chunks int
	start := func() {
		cur.Reset()
		blocks, runes, chunks = 1, partRoom+utf8.RuneCountInString("<p></p>"), 0
		if len(bodies) == 0 {
			runes += utf8.RuneCountInString(intro)
		}
	}
	flush := func() {
		bodies = append(bodies, cur.String())
		start()
	}
	start()
	for _, s := range sections {
		head, headBlocks, rows := s.render()
		for len(rows) > 0 {
			b := blocks + headBlocks
			n := runes + utf8.RuneCountInString(head) + len(tableEnd)
			k := 0
			for k < len(rows) && b+1 <= lim.blocks && n+utf8.RuneCountInString(rows[k]) <= lim.runes {
				b++
				n += utf8.RuneCountInString(rows[k])
				k++
			}
			if k == 0 {
				if chunks > 0 {
					flush()
					continue
				}
				k = 1
				b++
				n += utf8.RuneCountInString(rows[0])
			}
			cur.WriteString(head)
			for _, row := range rows[:k] {
				cur.WriteString(row)
			}
			cur.WriteString(tableEnd)
			blocks, runes = b, n
			chunks++
			rows = rows[k:]
			if len(rows) > 0 {
				flush()
			}
		}
	}
	bodies = append(bodies, cur.String())
	msgs := make([]string, len(bodies))
	for i, body := range bodies {
		var first []string
		if len(bodies) > 1 {
			first = append(first, fmt.Sprintf("Part %d of %d", i+1, len(bodies)))
		}
		if i == 0 {
			first = append(first, intro)
		}
		msgs[i] = "<p>" + strings.Join(first, "<br>") + "</p>" + body
	}
	return msgs
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

func (v variant) describe() string {
	if v.key == "" && v.version == 0 {
		return "no signing key or version in the attestation, not verified"
	}
	key := "no signing key"
	if v.key != "" {
		key = "key " + v.keyText()
	}
	state := "not verified"
	if v.verified {
		state = "verified"
	}
	return fmt.Sprintf("%s, version %d, %s", key, v.version, state)
}

func (v variant) keyText() string {
	if v.key == "" {
		return "none"
	}
	return clip(display(v.key), keyShown)
}

func (s sourceGroup) span(loc *time.Location) string {
	first := s.times[0].In(loc).Format(timeLayout)
	last := s.times[len(s.times)-1].In(loc).Format(timeLayout)
	if first == last {
		return first
	}
	return first + "–" + last
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

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func display(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '\uFFFD'
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}
