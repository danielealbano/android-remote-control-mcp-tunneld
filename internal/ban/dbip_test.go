package ban

import (
	"net/netip"
	"testing"
)

// dbipFixture uses ONLY placeholder country codes (XX, YY, ZZ).
const dbipFixture = "1.0.0.0,1.0.0.255,XX\n" +
	"2.0.0.0,2.0.255.255,YY\n" +
	"3.0.0.0,3.0.0.255,ZZ\n"

func TestExpandCountriesDirect(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", dbipFixture)
	prefixes, err := ExpandCountries(csv, map[string]struct{}{"XX": {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixes) == 0 {
		t.Fatal("expected prefixes for XX")
	}
	target := netip.MustParseAddr("1.0.0.5")
	found := false
	for _, pfxs := range prefixes {
		for _, p := range pfxs {
			if p.Contains(target) {
				found = true
			}
		}
	}
	if !found {
		t.Error("XX range must cover 1.0.0.5")
	}
	// Empty csvPath → error (caller warns-and-skips country entries).
	if _, err := ExpandCountries("", map[string]struct{}{"XX": {}}); err == nil {
		t.Error("empty csvPath must error")
	}
}

// TestLoad_GeoBanCarriesCountrySource verifies a matched geo-ban's Source names the country code and the
// ban-file line that requested it (not a generic "country-expansion" placeholder).
func TestLoad_GeoBanCarriesCountrySource(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", dbipFixture)
	f := writeBan(t, dir, "bans.txt", "# header comment\ncountry XX\n")
	e := NewEngine()
	if err := e.Load([]string{f}, csv, nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	src, ok := e.Match(mustAddr("1.0.0.5"))
	if !ok {
		t.Fatal("XX range must match")
	}
	if src.Reason != ReasonCountry {
		t.Errorf("reason = %q, want %q", src.Reason, ReasonCountry)
	}
	if src.Detail != "XX" {
		t.Errorf("detail = %q, want the country code XX", src.Detail)
	}
	if src.File != f {
		t.Errorf("file = %q, want the requesting ban file %q", src.File, f)
	}
	if src.Line != 2 {
		t.Errorf("line = %d, want 2 (the 'country XX' line)", src.Line)
	}
}

// TestExpandCountries_SemanticsPreserved pins the absent/zero-row/absent-code contract across the new
// map return shape.
func TestExpandCountries_SemanticsPreserved(t *testing.T) {
	dir := t.TempDir()
	// absent path (empty) → error
	if _, err := ExpandCountries("", map[string]struct{}{"XX": {}}); err == nil {
		t.Error("empty csvPath must error")
	}
	// nonexistent file → error
	if _, err := ExpandCountries(dir+"/nope.csv", map[string]struct{}{"XX": {}}); err == nil {
		t.Error("a nonexistent CSV must error")
	}
	// present-but-zero-parseable-rows → error
	bad := writeBan(t, dir, "bad.csv", "not,an,ip\nrow,at,all\n")
	if _, err := ExpandCountries(bad, map[string]struct{}{"XX": {}}); err == nil {
		t.Error("a zero-row CSV must error")
	}
	// valid CSV, absent wanted code → empty (non-nil) map, no error
	good := writeBan(t, dir, "good.csv", dbipFixture)
	out, err := ExpandCountries(good, map[string]struct{}{"QQ": {}})
	if err != nil {
		t.Fatalf("absent wanted code must be legal: %v", err)
	}
	if out == nil || len(out) != 0 {
		t.Errorf("absent wanted code must yield an empty non-nil map, got %v", out)
	}
}

func TestCountryExpandsAndMatches(t *testing.T) {
	dir := t.TempDir()
	csv := writeBan(t, dir, "dbip.csv", dbipFixture)
	f := writeBan(t, dir, "bans.txt", "country XX\n")
	e := NewEngine()
	if err := e.Load([]string{f}, csv, nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	src, ok := e.Match(mustAddr("1.0.0.5"))
	if !ok {
		t.Fatal("address in XX range must match")
	}
	if src.Reason != ReasonCountry {
		t.Errorf("reason = %q, want banned_country", src.Reason)
	}
	if _, ok := e.Match(mustAddr("9.9.9.9")); ok {
		t.Error("address outside any banned country must not match")
	}
}

func TestMissingCSVSkipsCountryOnly(t *testing.T) {
	dir := t.TempDir()
	f := writeBan(t, dir, "bans.txt", "country XX\nip 5.5.5.5\n")
	e := NewEngine()
	// No CSV configured → country entries skipped, ip still enforced.
	if err := e.Load([]string{f}, "", nil, discardLog()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.Match(mustAddr("5.5.5.5")); !ok {
		t.Error("ip entry must still be enforced when the CSV is absent")
	}
	if _, ok := e.Match(mustAddr("1.0.0.5")); ok {
		t.Error("country entries must be skipped when the CSV is absent")
	}
}
