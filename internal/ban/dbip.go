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
// returns (nil, err) when csvPath == "", the file is unreadable, OR it yields zero parseable rows
// (corrupt/empty): on the present-but-unusable case the caller keeps the previous snapshot, and it
// skip-and-warns ONLY when the CSV is absent. A valid CSV whose wanted country code is simply absent
// yields an empty (non-nil) map with no error.
//
// The file is tens of MB and parsed only on reload, so it is streamed with ReuseRecord.
func ExpandCountries(csvPath string, wanted map[string]struct{}) (map[string][]netip.Prefix, error) {
	if csvPath == "" {
		return nil, errors.New("no dbip-country-lite-csv configured")
	}
	f, err := os.Open(csvPath) // #nosec G304 -- operator-configured --dbip-country-lite-csv path (deployment trust boundary, not request-derived)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate stray rows; validate width per-row below
	r.ReuseRecord = true

	out := map[string][]netip.Prefix{}
	validRows := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(rec) < 3 {
			continue // skip a malformed/short row, keep going (matches the address-parse skip policy)
		}
		start, e1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		end, e2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		if e1 != nil || e2 != nil {
			continue
		}
		validRows++
		cc := strings.ToUpper(strings.TrimSpace(rec[2]))
		if _, ok := wanted[cc]; !ok {
			continue
		}
		rng := netipx.IPRangeFrom(start, end)
		if !rng.IsValid() {
			continue
		}
		out[cc] = append(out[cc], rng.Prefixes()...)
	}
	if validRows == 0 {
		// A present CSV that produced no parseable rows is corrupt/empty — error so the caller keeps the
		// previous snapshot rather than silently dropping every country ban (docs/ARCHITECTURE.md §6).
		return nil, fmt.Errorf("dbip csv %q produced no valid rows", csvPath)
	}
	return out, nil
}
