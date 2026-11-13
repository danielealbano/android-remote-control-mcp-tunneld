package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/telegram"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
)

const (
	unknownPlace   = "unknown"
	ownerBudget    = 30 * time.Second
	ownerLookups   = 4
	ownerRunes     = 128
	sourceApp      = "arc-busy-clients"
	lookupCrashMsg = "looking up a network owner crashed, so that address shows its owner as unknown"
)

type place struct {
	country string
	network string
}

type locator func(ctx context.Context, addrs []netip.Addr) []place

type countryRange struct {
	start, end netip.Addr
	code       string
}

func loadCountries(path string) (_ []countryRange, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open the DB-IP country file %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close the DB-IP country file %s: %w", path, cerr))
		}
	}()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	var out []countryRange
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		var perr *csv.ParseError
		if err != nil && !errors.As(err, &perr) {
			return nil, fmt.Errorf("read the DB-IP country file %s: %w", path, err)
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		start, e1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		end, e2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		if e1 != nil || e2 != nil || start.BitLen() != end.BitLen() || end.Less(start) {
			continue
		}
		out = append(out, countryRange{start: start, end: end, code: strings.ToUpper(strings.TrimSpace(rec[2]))})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the DB-IP country file %s has no valid row", path)
	}
	slices.SortFunc(out, func(a, b countryRange) int { return a.start.Compare(b.start) })
	return out, nil
}

func countryOf(ranges []countryRange, a netip.Addr) string {
	i, _ := slices.BinarySearchFunc(ranges, a, func(r countryRange, a netip.Addr) int {
		if r.start.Compare(a) <= 0 {
			return -1
		}
		return 1
	})
	if i == 0 {
		return ""
	}
	r := ranges[i-1]
	if r.start.BitLen() != a.BitLen() || r.end.Less(a) {
		return ""
	}
	return r.code
}

type prefixOverview struct {
	Data struct {
		ASNs []struct {
			ASN    int64  `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	} `json:"data"`
}

func lookupOwner(ctx context.Context, client *http.Client, base string, a netip.Addr) (string, error) {
	body, err := fetch(ctx, client, base+"?resource="+url.QueryEscape(a.String())+"&sourceapp="+sourceApp)
	if err != nil {
		return "", err
	}
	var v prefixOverview
	if err := json.Unmarshal(body, &v); err != nil {
		return "", fmt.Errorf("decode the network owner of %s: %w", a, err)
	}
	if len(v.Data.ASNs) == 0 {
		return "not announced", nil
	}
	names := make([]string, len(v.Data.ASNs))
	for i, n := range v.Data.ASNs {
		names[i] = fmt.Sprintf("AS%d %s", n.ASN, n.Holder)
	}
	return telegram.Clip(telegram.Display(strings.Join(names, ", ")), ownerRunes), nil
}

func newLocator(client *http.Client, logger *slog.Logger, countryFile, ownerURL string) locator {
	return func(ctx context.Context, addrs []netip.Addr) []place {
		out := make([]place, len(addrs))
		for i := range out {
			out[i] = place{country: unknownPlace, network: unknownPlace}
		}
		ranges, err := loadCountries(countryFile)
		if err != nil {
			logger.Warn("the DB-IP country file could not be read, so the alert shows every country as unknown", "file", countryFile, "err", err)
		} else {
			for i, a := range addrs {
				if code := countryOf(ranges, a); code != "" {
					out[i].country = code
				}
			}
		}
		lctx, cancel := context.WithTimeout(ctx, ownerBudget)
		defer cancel()
		var (
			mu     sync.Mutex
			failed int
		)
		var g errgroup.Group
		g.SetLimit(ownerLookups)
		for i, a := range addrs {
			g.Go(func() (err error) {
				defer func() {
					if err != nil {
						mu.Lock()
						failed++
						mu.Unlock()
					}
				}()
				rctx := report.WithScope(lctx)
				report.SetAttrs(rctx, slog.String("address", a.String()))
				defer report.RecoverWith(rctx, logger, "looking up a network owner", lookupCrashMsg, func() {
					err = fmt.Errorf("looking up the network owner of %s crashed", a)
				})
				name, err := lookupOwner(rctx, client, ownerURL, a)
				if err != nil {
					return err
				}
				out[i].network = name
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			logger.Warn("the network owners of some addresses could not be looked up, so they show as unknown",
				"addresses", failed, "of", len(addrs), "err", err)
		}
		return out
	}
}
