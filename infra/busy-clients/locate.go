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

func countriesOf(path string, addrs []netip.Addr) (_ map[netip.Addr]string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open the DB-IP country file %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("close the DB-IP country file %s: %w", path, cerr))
		}
	}()
	sorted := slices.Clone(addrs)
	slices.SortFunc(sorted, netip.Addr.Compare)
	sorted = slices.Compact(sorted)
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	found := make(map[netip.Addr]string, len(sorted))
	valid := 0
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
		code := strings.ToUpper(strings.TrimSpace(rec[2]))
		if !isCountryCode(code) {
			continue
		}
		valid++
		i, _ := slices.BinarySearchFunc(sorted, start, netip.Addr.Compare)
		for ; i < len(sorted) && !end.Less(sorted[i]); i++ {
			if _, done := found[sorted[i]]; !done {
				found[sorted[i]] = code
			}
		}
	}
	if valid == 0 {
		return nil, fmt.Errorf("the DB-IP country file %s has no valid row", path)
	}
	return found, nil
}

func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

func ownerEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("the network owner lookup address %q cannot be parsed: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the network owner lookup address %q is not an http or https address with a host", raw)
	}
	return u, nil
}

type prefixOverview struct {
	Status   string     `json:"status"`
	Messages [][]string `json:"messages"`
	Data     struct {
		Announced *bool `json:"announced"`
		ASNs      []struct {
			ASN    int64  `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
	} `json:"data"`
}

func lookupOwner(ctx context.Context, client *http.Client, base *url.URL, a netip.Addr) (string, error) {
	u := *base
	q := u.Query()
	q.Set("resource", a.String())
	q.Set("sourceapp", sourceApp)
	u.RawQuery = q.Encode()
	code, body, err := get(ctx, client, u.String())
	if err != nil {
		return "", err
	}
	var v prefixOverview
	derr := json.Unmarshal(body, &v)
	if code != http.StatusOK || derr == nil && v.Status != "ok" {
		return "", fmt.Errorf("the network owner lookup of %s answered with HTTP status %d and status %q: %s", a, code, v.Status, ripeExplanation(v.Messages, body, derr))
	}
	if derr != nil {
		return "", fmt.Errorf("decode the network owner of %s: %w", a, derr)
	}
	if v.Data.Announced == nil {
		return "", fmt.Errorf("the network owner lookup of %s did not say whether the address is announced", a)
	}
	if !*v.Data.Announced || len(v.Data.ASNs) == 0 {
		return "not announced", nil
	}
	names := make([]string, len(v.Data.ASNs))
	for i, n := range v.Data.ASNs {
		names[i] = fmt.Sprintf("AS%d %s", n.ASN, n.Holder)
	}
	return telegram.Clip(telegram.Display(strings.Join(names, ", ")), ownerRunes), nil
}

func ripeExplanation(messages [][]string, body []byte, derr error) string {
	if derr != nil || len(messages) == 0 {
		return telegram.Clip(telegram.Display(string(body)), ownerRunes)
	}
	parts := make([]string, len(messages))
	for i, m := range messages {
		parts[i] = strings.Join(m, ": ")
	}
	return telegram.Clip(telegram.Display(strings.Join(parts, "; ")), ownerRunes)
}

func lookupBudget(ctx context.Context, budget time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		return min(budget, time.Until(deadline)/2)
	}
	return budget
}

func guardedLookup(ctx context.Context, logger *slog.Logger, client *http.Client, owners *url.URL, a netip.Addr) (name string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rctx := report.WithScope(ctx)
	report.SetAttrs(rctx, slog.String("address", a.String()))
	defer report.RecoverWith(rctx, logger, "looking up a network owner", lookupCrashMsg, func() {
		name, err = "", fmt.Errorf("looking up the network owner of %s crashed", a)
	})
	return lookupOwner(rctx, client, owners, a)
}

func newLocator(client *http.Client, logger *slog.Logger, countryFile string, owners *url.URL, budget time.Duration) locator {
	return func(ctx context.Context, addrs []netip.Addr) []place {
		out := make([]place, len(addrs))
		for i := range out {
			out[i] = place{country: unknownPlace, network: unknownPlace}
		}
		countries, err := countriesOf(countryFile, addrs)
		if err != nil {
			logger.Warn("the DB-IP country file could not be read, so the alert shows every country as unknown", "file", countryFile, "err", err)
		}
		for i, a := range addrs {
			if code, ok := countries[a]; ok {
				out[i].country = code
			}
		}
		lctx, cancel := context.WithTimeout(ctx, lookupBudget(ctx, budget))
		defer cancel()
		var (
			mu      sync.Mutex
			cutOff  int
			stopped int
			wg      sync.WaitGroup
		)
		slots := make(chan struct{}, ownerLookups)
		for i, a := range addrs {
			slots <- struct{}{}
			wg.Go(func() {
				defer func() { <-slots }()
				name, err := guardedLookup(lctx, logger, client, owners, a)
				switch {
				case err == nil:
					out[i].network = name
				case errors.Is(lctx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded):
					mu.Lock()
					cutOff++
					mu.Unlock()
				case errors.Is(lctx.Err(), context.Canceled) && errors.Is(err, context.Canceled):
					mu.Lock()
					stopped++
					mu.Unlock()
				default:
					logger.Warn("the network owner of an address could not be looked up, so it shows as unknown", "address", a, "err", err)
				}
			})
		}
		wg.Wait()
		if cutOff > 0 {
			logger.Warn("the time for the network owner lookups ran out, so some addresses show their owner as unknown",
				"addresses", cutOff, "of", len(addrs))
		}
		if stopped > 0 {
			logger.Warn("the run was stopped before the network owner lookups finished, so some addresses show their owner as unknown",
				"addresses", stopped, "of", len(addrs))
		}
		return out
	}
}
