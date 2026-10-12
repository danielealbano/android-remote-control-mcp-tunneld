package ban

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"go4.org/netipx"
)

// ExpandCountries reads a DB-IP Country Lite CSV (columns: start_ip,end_ip,country_code) and returns
// the covering prefixes for the requested country codes (via netipx.IPRange.Prefixes()), keyed by
// country code so a matched geo-ban can report WHICH country fired. Malformed rows are skipped. It
// returns err when csvPath == "", the file is unreadable, OR it yields zero parseable rows
// (corrupt/empty): on the present-but-unusable case the caller keeps the previous snapshot, and it
// skip-and-warns ONLY when the CSV is absent. A valid CSV whose wanted country code is simply absent
// yields an empty (non-nil) map with no error.
//
// The file is tens of MB and parsed only on reload, so it is streamed with ReuseRecord.
func ExpandCountries(csvPath string, wanted map[string]struct{}) (out map[string][]netip.Prefix, skipped SkippedRows, err error) {
	if csvPath == "" {
		return nil, SkippedRows{}, errors.New("no dbip-country-lite-csv configured")
	}
	f, err := os.Open(csvPath) // #nosec G304 -- operator-configured --dbip-country-lite-csv path (deployment trust boundary, not request-derived)
	if err != nil {
		return nil, SkippedRows{}, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			out, err = nil, errors.Join(err, fmt.Errorf("close dbip csv %q: %w", csvPath, cerr))
		}
	}()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate stray rows; validate width per-row below
	r.ReuseRecord = true

	out = map[string][]netip.Prefix{}
	validRows := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		var perr *csv.ParseError
		if err != nil && !errors.As(err, &perr) {
			return nil, skipped, fmt.Errorf("read dbip csv %q: %w", csvPath, err)
		}
		if err != nil || len(rec) < 3 {
			skipped.Malformed++
			continue // skip a malformed/short row, keep going (matches the address-parse skip policy)
		}
		start, e1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		end, e2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		if e1 != nil || e2 != nil {
			skipped.BadAddress++
			continue
		}
		validRows++
		cc := strings.ToUpper(strings.TrimSpace(rec[2]))
		if _, ok := wanted[cc]; !ok {
			continue
		}
		rng := netipx.IPRangeFrom(start, end)
		if !rng.IsValid() {
			skipped.InvalidRange++
			continue
		}
		out[cc] = append(out[cc], rng.Prefixes()...)
	}
	if validRows == 0 {
		// A present CSV that produced no parseable rows is corrupt/empty — error so the caller keeps the
		// previous snapshot rather than silently dropping every country ban (docs/ARCHITECTURE.md §6).
		return nil, skipped, fmt.Errorf("dbip csv %q produced no valid rows", csvPath)
	}
	return out, skipped, nil
}

type SkippedRows struct {
	Malformed    int
	BadAddress   int
	InvalidRange int
}

func (s SkippedRows) Total() int { return s.Malformed + s.BadAddress + s.InvalidRange }
