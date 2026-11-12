package telegram

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func testSection(name string, rows int) Section {
	s := Section{Heading: name, Note: "note", Columns: []string{"A", "B"}}
	for i := range rows {
		s.Rows = append(s.Rows, []Cell{Text(name), Text("row" + strconv.Itoa(i))})
	}
	return s
}

func TestPack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sections []Section
		lim      Limits
		want     int
	}{
		{name: "a report without attempts is the intro alone", lim: Limits{Blocks: 500, Runes: 32768}, want: 1},
		{name: "everything that fits is one message", sections: []Section{testSection("x", 3), testSection("y", 3)}, lim: Limits{Blocks: 500, Runes: 32768}, want: 1},
		{name: "too many rows split by blocks", sections: []Section{testSection("x", 30)}, lim: Limits{Blocks: 15, Runes: 32768}, want: 3},
		{name: "too much text splits by characters", sections: []Section{testSection("x", 30)}, lim: Limits{Blocks: 500, Runes: 600}, want: 3},
		{name: "a section that no longer fits starts the next message", sections: []Section{testSection("x", 8), testSection("y", 8)}, lim: Limits{Blocks: 15, Runes: 32768}, want: 2},
		{name: "a row larger than a message still goes out alone", sections: []Section{testSection("x", 2)}, lim: Limits{Blocks: 500, Runes: 10}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs := Pack([]string{"intro"}, tc.sections, tc.lim)
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
				if tc.lim.Runes > 100 && (utf8.RuneCountInString(m) > tc.lim.Runes || strings.Count(m, "<tr>")+strings.Count(m, "<h4>")+strings.Count(m, "<p>")+strings.Count(m, "<table") > tc.lim.Blocks) {
					t.Fatalf("message %d is over the limits %+v: %s", i+1, tc.lim, m)
				}
				for _, s := range tc.sections {
					if strings.Contains(m, "<td>"+s.Heading+"</td>") && !strings.Contains(m, "<h4>"+s.Heading+"</h4><p>note</p>"+tableStart+"<tr><th>A</th><th>B</th></tr>") {
						t.Fatalf("message %d has rows of %s without its heading and table header", i+1, s.Heading)
					}
					for j := range s.Rows {
						rows[s.Heading+"/"+strconv.Itoa(j)] += strings.Count(m, "<td>"+s.Heading+"</td><td>row"+strconv.Itoa(j)+"</td>")
					}
				}
			}
			for _, s := range tc.sections {
				for j := range s.Rows {
					if n := rows[s.Heading+"/"+strconv.Itoa(j)]; n != 1 {
						t.Fatalf("row %d of %s appears %d times", j, s.Heading, n)
					}
				}
			}
		})
	}
}

func TestPack_EscapesEveryValue(t *testing.T) {
	t.Parallel()
	s := Section{Heading: "<b>h</b>", Note: "a & b", Columns: []string{"<th>"}, Rows: [][]Cell{{Text("</td><script>")}}}
	msgs := Pack([]string{"<i>intro</i>"}, []Section{s}, Limits{Blocks: 500, Runes: 32768})
	want := "<p>&lt;i&gt;intro&lt;/i&gt;</p><h4>&lt;b&gt;h&lt;/b&gt;</h4><p>a &amp; b</p>" + tableStart +
		"<tr><th>&lt;th&gt;</th></tr><tr><td>&lt;/td&gt;&lt;script&gt;</td></tr>" + tableEnd
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}

func TestPack_LinkCell(t *testing.T) {
	t.Parallel()
	s := Section{Heading: "h", Columns: []string{"A", "B"}, Rows: [][]Cell{{{Text: "<a>", URL: `https://x.test/?a=1&b="2"`}, Text("plain")}}}
	msgs := Pack([]string{"intro"}, []Section{s}, Limits{Blocks: 500, Runes: 32768})
	want := "<p>intro</p><h4>h</h4>" + tableStart + "<tr><th>A</th><th>B</th></tr>" +
		`<tr><td><a href="https://x.test/?a=1&amp;b=&#34;2&#34;">&lt;a&gt;</a></td><td>plain</td></tr>` + tableEnd
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}

func TestClipAndDisplay(t *testing.T) {
	t.Parallel()
	if got := Clip("abcdef", 3); got != "abc…" {
		t.Errorf("Clip = %q, want %q", got, "abc…")
	}
	if got := Clip("abc", 3); got != "abc" {
		t.Errorf("Clip of a short text = %q, want it unchanged", got)
	}
	if got := Display("a\n\u202eb\xff"); got != "a\uFFFD\uFFFDb\uFFFD" {
		t.Errorf("Display = %q", got)
	}
}
