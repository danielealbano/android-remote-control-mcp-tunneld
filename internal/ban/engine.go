package ban

import (
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"net/netip"
	"sync/atomic"

	"github.com/gaissmai/bart"
)

// snapshot is an immutable view swapped in atomically on each successful Load. Readers hold the old
// pointer unaffected during a reload (lock-free hot path).
type snapshot struct {
	table *bart.Table[Source]
	names map[string]Source
}

func emptySnapshot() *snapshot {
	return &snapshot{table: &bart.Table[Source]{}, names: map[string]Source{}}
}

// Engine is the hot-reloadable ban table. The zero-value is NOT usable; construct via NewEngine.
type Engine struct {
	current atomic.Pointer[snapshot]
}

// NewEngine returns an engine holding an EMPTY non-nil snapshot, so Match/MatchTunnel before any
// Load return (Source{}, false) — never a nil-pointer panic on the hot path.
func NewEngine() *Engine {
	e := &Engine{}
	e.current.Store(emptySnapshot())
	return e
}

// Match reports whether ip is banned (LPM lookup) and, if so, the matched Source.
func (e *Engine) Match(ip netip.Addr) (Source, bool) {
	return e.current.Load().table.Lookup(ip)
}

// MatchTunnel reports whether the tunnel name is banned.
func (e *Engine) MatchTunnel(name string) (Source, bool) {
	s := e.current.Load()
	if src, ok := s.names[name]; ok {
		return src, true
	}
	return Source{}, false
}

// Load parses all files, expands country entries against the DB-IP CSV, builds a fresh table, and
// atomically swaps it in. Absent files (not-exist) and malformed lines are warned-and-skipped. An
// ABSENT CSV skips only the country entries (skip-and-warn, first deploy); a PRESENT CSV that yields
// zero parseable rows returns an error and keeps the previous snapshot; a valid CSV whose wanted
// country code is absent is legal (empty result, no error). A HARD read error on a configured file
// (e.g. an I/O error or a path that is a directory — NOT not-exist) returns a non-nil error WITHOUT
// swapping, so the previous snapshot is preserved (never emptied on error). A path in `required` (one
// that existed at the last successful load) that has now VANISHED returns an error WITHOUT swapping —
// a mid-load deletion is an operator error, never a request to unban.
func (e *Engine) Load(files []string, csvPath string, required map[string]struct{}, log *slog.Logger) error {
	s, err := e.build(files, csvPath, required, log)
	if err != nil {
		return err
	}
	e.commit(s)
	return nil
}

// build parses all files + expands country entries into a FRESH snapshot WITHOUT swapping it in, so a
// caller (the watcher) can verify input stability before committing. Absent/vanished/corrupt/zero-row
// semantics are identical to Load — see the Load doc comment.
func (e *Engine) build(files []string, csvPath string, required map[string]struct{}, log *slog.Logger) (*snapshot, error) {
	table := &bart.Table[Source]{}
	names := map[string]Source{}
	countries := map[string]Source{}

	for _, f := range files {
		p, err := parseFile(f, log)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if _, req := required[f]; req {
					log.Error("a required ban file disappeared; keeping the previous bans", "file", f)
					return nil, err // do NOT swap — a previously-loaded file MUST NOT silently unban
				}
				log.Warn("a ban file does not exist yet; it is loaded once it appears", "file", f)
				continue
			}
			log.Warn("could not read a ban file; keeping the previous bans", "file", f, "err", err)
			return nil, err // do NOT swap — preserve the previous snapshot
		}
		for _, ps := range p.prefixes {
			table.Insert(ps.prefix, ps.source)
		}
		maps.Copy(names, p.names)
		// last writer wins; each source carries the requesting file/line/Detail=cc.
		maps.Copy(countries, p.countries)
	}

	if len(countries) > 0 {
		wanted := make(map[string]struct{}, len(countries))
		for cc := range countries {
			wanted[cc] = struct{}{}
		}
		byCC, skipped, err := ExpandCountries(csvPath, wanted)
		switch {
		case err == nil:
			if skipped.Total() > 0 {
				log.Warn("skipped unreadable rows in the country database (DB-IP CSV)", "csv", csvPath, "malformed", skipped.Malformed,
					"bad_address", skipped.BadAddress, "invalid_range", skipped.InvalidRange)
			}
			for cc, pfxs := range byCC {
				src := countries[cc] // the ban-file entry that requested this country (file/line/Detail=cc)
				for _, pfx := range pfxs {
					table.Insert(pfx, src)
				}
			}
		case csvPath == "" || errors.Is(err, fs.ErrNotExist):
			if _, req := required[csvPath]; req {
				log.Error("the required country database (DB-IP CSV) disappeared; keeping the previous bans", "csv", csvPath)
				return nil, err // do NOT swap — a previously-loaded CSV MUST NOT silently drop country bans
			}
			// First-deploy / geo-off: the CSV does not exist yet — skip country entries, keep ip/cidr.
			log.Warn("country bans are not applied because the country database (DB-IP CSV) is missing; IP and network bans still apply", "csv", csvPath, "err", err)
		default:
			// A configured CSV is present but failed to parse: do NOT silently drop active geo bans.
			log.Warn("could not turn the country bans into address ranges from the country database; keeping the previous bans", "csv", csvPath, "err", err)
			return nil, err // preserve the previous snapshot (never swap in one missing the country layer)
		}
	}

	return &snapshot{table: table, names: names}, nil
}

// commit atomically swaps a built snapshot in.
func (e *Engine) commit(s *snapshot) { e.current.Store(s) }
