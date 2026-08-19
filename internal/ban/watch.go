package ban

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Watch polls a per-path (exists, mtime, size) fingerprint across all ban files + the CSV every
// `poll`; on ANY change — including a deletion or a replacement with an equal/older mtime — it reloads
// the engine and, on a SUCCESSFUL load, invokes onReload(e) (nil-safe). The initial load happens once
// before the poll loop (and fires onReload on success). A load error keeps the previous snapshot
// (never empties the table), does NOT advance the recorded fingerprint (so it retries on the next
// tick), and does NOT fire onReload.
//
// onReload is how live name/fingerprint revocation reaches the phone control manager
// (phoneconn.Manager.EvictBanned; see docs/ARCHITECTURE.md §7).
func Watch(ctx context.Context, e *Engine, files []string, csvPath string, poll time.Duration, onReload func(*Engine), log *slog.Logger) {
	w := &watcher{e: e, files: files, csv: csvPath, onReload: onReload, log: log}
	w.initial()

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick()
		}
	}
}

// fileState is one configured path's (exists, mtime, size) fingerprint.
type fileState struct {
	exists  bool
	modTime time.Time
	size    int64
}

// watcher holds the poll state; split out so tests can drive initial()/tick() deterministically
// without depending on ticker timing.
type watcher struct {
	e        *Engine
	files    []string
	csv      string
	onReload func(*Engine)
	log      *slog.Logger
	last     map[string]fileState
	// stat is the per-path fingerprint source; nil means os.Stat. Tests override it to script a torn
	// read (a file changing between the pre- and post-load fingerprints).
	stat func(string) fileState
}

func (w *watcher) initial() {
	cur := w.fingerprint()
	if err := w.e.Load(w.files, w.csv, nil, w.log); err != nil {
		w.log.Warn("initial ban load error; engine stays at empty/previous snapshot until next successful load", "err", err)
		return // do NOT record cur — retry on the next tick
	}
	w.last = cur
	if w.onReload != nil {
		w.onReload(w.e)
	}
}

func (w *watcher) tick() {
	cur := w.fingerprint()
	if w.last != nil && sameStates(w.last, cur) {
		return
	}
	// A path that existed at the last successful load and has now VANISHED is an operator error or a
	// tooling race, NOT a request to unban: keep the previous snapshot and retry every tick (delete
	// the entry from config + restart to drop a file on purpose). Load's `required` set
	// enforces the same refusal even when the deletion lands between this check and the file reads.
	req := w.required()
	if p, vanished := w.vanished(cur); vanished {
		w.log.Error("ban input file disappeared; refusing reload and keeping the previous bans", "file", p)
		return
	}
	// Torn-read guard: a non-atomic external writer can be caught mid-truncate; reload until the
	// fingerprint is stable across the load (bounded).
	for attempt := 0; attempt < 3; attempt++ {
		if err := w.e.Load(w.files, w.csv, req, w.log); err != nil {
			w.log.Warn("ban reload error; keeping previous snapshot (will retry)", "err", err)
			return
		}
		after := w.fingerprint()
		if p, vanished := w.vanished(after); vanished {
			// The deletion landed mid-tick: Load already refused via `required`, but a stability pass
			// here must never commit the vanished state as the new baseline.
			w.log.Error("ban input file disappeared during reload; keeping the previous bans", "file", p)
			return
		}
		if sameStates(cur, after) {
			w.last = cur
			if w.onReload != nil {
				w.onReload(w.e)
			}
			return
		}
		cur = after
	}
	w.log.Warn("ban files kept changing during reload; retrying next tick")
}

// required returns the paths present at the last successful load (they MUST still exist).
func (w *watcher) required() map[string]struct{} {
	req := map[string]struct{}{}
	for p, st := range w.last {
		if st.exists {
			req[p] = struct{}{}
		}
	}
	return req
}

// vanished reports the first last-loaded path absent from states, if any.
func (w *watcher) vanished(states map[string]fileState) (string, bool) {
	for p, prev := range w.last {
		if prev.exists && !states[p].exists {
			return p, true
		}
	}
	return "", false
}

// fingerprint records (exists, mtime, size) for every configured path so a change of ANY kind —
// including deletion or a replacement with an equal/older mtime — is detected.
func (w *watcher) fingerprint() map[string]fileState {
	states := map[string]fileState{}
	paths := w.files
	if w.csv != "" {
		paths = append(append([]string{}, w.files...), w.csv)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		states[p] = w.statePath(p)
	}
	return states
}

// statePath returns one path's (exists, mtime, size) fingerprint via the stat seam (os.Stat by default).
func (w *watcher) statePath(p string) fileState {
	if w.stat != nil {
		return w.stat(p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return fileState{exists: false}
	}
	return fileState{exists: true, modTime: fi.ModTime(), size: fi.Size()}
}

func sameStates(a, b map[string]fileState) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || av != bv {
			return false
		}
	}
	return true
}
