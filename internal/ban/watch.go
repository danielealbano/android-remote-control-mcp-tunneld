package ban

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// NewWatcher builds the poll state. Initial() runs the ONE startup load synchronously (before the caller
// binds listeners); Run() then polls a per-path (exists, mtime, size) fingerprint across all ban files +
// the CSV every `poll` and, on ANY change, reloads with build-verify-commit.
//
// onReload (passed to Run) is how live name/fingerprint revocation reaches the phone control manager
// (phoneconn.Manager.EvictBanned; see docs/ARCHITECTURE.md §7).
func NewWatcher(e *Engine, files []string, csvPath string, poll time.Duration, log *slog.Logger) *watcher {
	return &watcher{e: e, files: files, csv: csvPath, poll: poll, log: log}
}

// Initial performs the single startup load and records the baseline fingerprint (and thus the `required`
// set). It does NOT fire onReload (no live connections exist yet). A load error leaves the baseline
// unrecorded so Run() retries on the first tick (best-effort, matching the previous behavior).
func (w *watcher) Initial() {
	cur := w.fingerprint()
	if err := w.e.Load(w.files, w.csv, nil, w.log); err != nil {
		w.log.Warn("initial ban load error; engine stays at empty snapshot until a successful load", "err", err)
		return // do NOT record cur — retry on the next tick
	}
	w.last = cur
}

// Run polls until ctx is done; onReload fires on each SUCCESSFUL reload after a detected change.
func (w *watcher) Run(ctx context.Context, onReload func(*Engine)) {
	ticker := time.NewTicker(w.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.tick(onReload)
		}
	}
}

// fileState is one configured path's (exists, mtime, size) fingerprint.
type fileState struct {
	exists  bool
	modTime time.Time
	size    int64
}

// watcher holds the poll state; split out so tests can drive Initial()/tick() deterministically
// without depending on ticker timing.
type watcher struct {
	e     *Engine
	files []string
	csv   string
	poll  time.Duration
	log   *slog.Logger
	last  map[string]fileState
	// stat is the per-path fingerprint source; nil means os.Stat. Tests override it to script a torn
	// read (a file changing between the pre- and post-load fingerprints).
	stat func(string) fileState
}

func (w *watcher) tick(onReload func(*Engine)) {
	cur := w.fingerprint()
	if w.last != nil && sameStates(w.last, cur) {
		return
	}
	// A path that existed at the last successful load and has now VANISHED is an operator error or a
	// tooling race, NOT a request to unban: keep the previous snapshot and retry every tick (delete
	// the entry from config + restart to drop a file on purpose). build's `required` set
	// enforces the same refusal even when the deletion lands between this check and the file reads.
	req := w.required()
	if p, vanished := w.vanished(cur); vanished {
		w.log.Error("ban input file disappeared; refusing reload and keeping the previous bans", "file", p)
		return
	}
	// Torn-read guard: a non-atomic external writer can be caught mid-truncate. Build the snapshot
	// WITHOUT swapping, and commit it ONLY once the fingerprint is stable across the build (bounded), so
	// a torn read never becomes the live snapshot.
	for range 3 {
		snap, err := w.e.build(w.files, w.csv, req, w.log)
		if err != nil {
			w.log.Warn("ban reload error; keeping previous snapshot (will retry)", "err", err)
			return
		}
		after := w.fingerprint()
		if p, vanished := w.vanished(after); vanished {
			// The deletion landed mid-tick: build already refused via `required`, but a stability pass
			// here must never commit the vanished state as the new baseline.
			w.log.Error("ban input file disappeared during reload; keeping the previous bans", "file", p)
			return
		}
		if sameStates(cur, after) {
			w.e.commit(snap) // swap in ONLY a snapshot built from a stable read
			w.last = cur
			if onReload != nil {
				onReload(w.e)
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
