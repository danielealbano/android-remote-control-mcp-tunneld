package telegram

import (
	"fmt"
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	partRoom   = 32
	tableStart = "<table bordered striped compact>"
	tableEnd   = "</table>"
)

type Cell struct {
	Text string
	URL  string
}

func Text(s string) Cell { return Cell{Text: s} }

type Section struct {
	Heading string
	Note    string
	Columns []string
	Rows    [][]Cell
}

type Limits struct {
	Blocks int
	Runes  int
}

func (s Section) render() (head string, blocks int, rows []string) {
	var b strings.Builder
	b.WriteString("<h4>" + html.EscapeString(s.Heading) + "</h4>")
	blocks = 3
	if s.Note != "" {
		b.WriteString("<p>" + html.EscapeString(s.Note) + "</p>")
		blocks++
	}
	b.WriteString(tableStart + "<tr>")
	for _, c := range s.Columns {
		b.WriteString("<th>" + html.EscapeString(c) + "</th>")
	}
	b.WriteString("</tr>")
	rows = make([]string, len(s.Rows))
	for i, row := range s.Rows {
		var rb strings.Builder
		rb.WriteString("<tr>")
		for _, c := range row {
			if c.URL == "" {
				rb.WriteString("<td>" + html.EscapeString(c.Text) + "</td>")
				continue
			}
			rb.WriteString(`<td><a href="` + html.EscapeString(c.URL) + `">` + html.EscapeString(c.Text) + "</a></td>")
		}
		rb.WriteString("</tr>")
		rows[i] = rb.String()
	}
	return b.String(), blocks, rows
}

func Pack(lead []string, sections []Section, lim Limits) []string {
	msgs, _ := PackRows(lead, sections, lim)
	return msgs
}

func PackRows(lead []string, sections []Section, lim Limits) ([]string, []int) {
	escaped := make([]string, len(lead))
	for i, l := range lead {
		escaped[i] = html.EscapeString(l)
	}
	intro := strings.Join(escaped, "<br>")
	var bodies []string
	var counts []int
	var cur strings.Builder
	var blocks, runes, chunks, held int
	start := func() {
		cur.Reset()
		blocks, runes, chunks, held = 1, partRoom+utf8.RuneCountInString("<p></p>"), 0, 0
		if len(bodies) == 0 {
			runes += utf8.RuneCountInString(intro)
		}
	}
	flush := func() {
		bodies = append(bodies, cur.String())
		counts = append(counts, held)
		start()
	}
	start()
	for _, s := range sections {
		head, headBlocks, rows := s.render()
		for len(rows) > 0 {
			b := blocks + headBlocks
			n := runes + utf8.RuneCountInString(head) + len(tableEnd)
			k := 0
			for k < len(rows) && b+1 <= lim.Blocks && n+utf8.RuneCountInString(rows[k]) <= lim.Runes {
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
			held += k
			rows = rows[k:]
			if len(rows) > 0 {
				flush()
			}
		}
	}
	bodies = append(bodies, cur.String())
	counts = append(counts, held)
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
	return msgs, counts
}

func Clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func Display(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '\uFFFD'
		}
		return r
	}, strings.ToValidUTF8(s, "\uFFFD"))
}
