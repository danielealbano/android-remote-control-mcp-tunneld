package telegram_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
)

const (
	tableStart = "<table bordered striped compact>"
	tableEnd   = "</table>"
)

func testSection(name string, rows int) telegram.Section {
	s := telegram.Section{Heading: name, Note: "note", Columns: []string{"A", "B"}}
	for i := range rows {
		s.Rows = append(s.Rows, []telegram.Cell{telegram.Text(name), telegram.Text("row" + strconv.Itoa(i))})
	}
	return s
}

func TestPack(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		sections []telegram.Section
		lim      telegram.Limits
		want     int
	}{
		{name: "a report without attempts is the intro alone", lim: telegram.Limits{Blocks: 500, Runes: 32768}, want: 1},
		{name: "everything that fits is one message", sections: []telegram.Section{testSection("x", 3), testSection("y", 3)}, lim: telegram.Limits{Blocks: 500, Runes: 32768}, want: 1},
		{name: "too many rows split by blocks", sections: []telegram.Section{testSection("x", 30)}, lim: telegram.Limits{Blocks: 15, Runes: 32768}, want: 3},
		{name: "too much text splits by characters", sections: []telegram.Section{testSection("x", 30)}, lim: telegram.Limits{Blocks: 500, Runes: 600}, want: 3},
		{name: "a section that no longer fits starts the next message", sections: []telegram.Section{testSection("x", 8), testSection("y", 8)}, lim: telegram.Limits{Blocks: 15, Runes: 32768}, want: 2},
		{name: "a row larger than a message still goes out alone", sections: []telegram.Section{testSection("x", 2)}, lim: telegram.Limits{Blocks: 500, Runes: 10}, want: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msgs, counts := telegram.PackRows([]string{"intro"}, tc.sections, tc.lim)
			if len(msgs) != tc.want || len(counts) != len(msgs) {
				t.Fatalf("got %d messages and %d row counts, want %d: %q", len(msgs), len(counts), tc.want, msgs)
			}
			if plain := telegram.Pack([]string{"intro"}, tc.sections, tc.lim); !slices.Equal(plain, msgs) {
				t.Fatalf("Pack and PackRows disagree: %q vs %q", plain, msgs)
			}
			total, packed := 0, 0
			for _, s := range tc.sections {
				total += len(s.Rows)
			}
			for i, m := range msgs {
				if n := strings.Count(m, "<tr><td>"); n != counts[i] {
					t.Fatalf("message %d holds %d rows but its count is %d", i+1, n, counts[i])
				}
				packed += counts[i]
			}
			if packed != total {
				t.Fatalf("the row counts add up to %d, want %d", packed, total)
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
	s := telegram.Section{Heading: "<b>h</b>", Note: "a & b", Columns: []string{"<th>"}, Rows: [][]telegram.Cell{{telegram.Text("</td><script>")}}}
	msgs := telegram.Pack([]string{"<i>intro</i>"}, []telegram.Section{s}, telegram.Limits{Blocks: 500, Runes: 32768})
	want := "<p>&lt;i&gt;intro&lt;/i&gt;</p><h4>&lt;b&gt;h&lt;/b&gt;</h4><p>a &amp; b</p>" + tableStart +
		"<tr><th>&lt;th&gt;</th></tr><tr><td>&lt;/td&gt;&lt;script&gt;</td></tr>" + tableEnd
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}

func TestPack_LinkCell(t *testing.T) {
	t.Parallel()
	s := telegram.Section{Heading: "h", Columns: []string{"A", "B"}, Rows: [][]telegram.Cell{{{Text: "<a>", URL: `https://x.test/?a=1&b="2"`}, telegram.Text("plain")}}}
	msgs := telegram.Pack([]string{"intro"}, []telegram.Section{s}, telegram.Limits{Blocks: 500, Runes: 32768})
	want := "<p>intro</p><h4>h</h4>" + tableStart + "<tr><th>A</th><th>B</th></tr>" +
		`<tr><td><a href="https://x.test/?a=1&amp;b=&#34;2&#34;">&lt;a&gt;</a></td><td>plain</td></tr>` + tableEnd
	if len(msgs) != 1 || msgs[0] != want {
		t.Fatalf("messages = %q\nwant       %q", msgs, want)
	}
}

func TestClip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "a long text is cut and marked", in: "abcdef", want: "abc…"},
		{name: "a text of the limit is unchanged", in: "abc", want: "abc"},
		{name: "runes, not bytes, are counted", in: "äöüß", want: "äöü…"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := telegram.Clip(tc.in, 3); got != tc.want {
				t.Fatalf("telegram.Clip(%q, 3) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestDisplay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain text is unchanged", in: "dev.example.app", want: "dev.example.app"},
		{name: "control and direction characters are replaced", in: "a\n\u202eb", want: "a\uFFFD\uFFFDb"},
		{name: "invalid UTF-8 is replaced", in: "b\xff", want: "b\uFFFD"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := telegram.Display(tc.in); got != tc.want {
				t.Fatalf("telegram.Display(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
