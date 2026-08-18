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
}

func (w *watcher) initial() {
	cur := w.fingerprint()
	if err := w.e.Load(w.files, w.csv, w.log); err != nil {
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
	if err := w.e.Load(w.files, w.csv, w.log); err != nil {
		w.log.Warn("ban reload error; keeping previous snapshot (will retry)", "err", err)
		return // do NOT advance w.last — retry on the next tick
	}
	w.last = cur
	if w.onReload != nil {
		w.onReload(w.e)
	}
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
		fi, err := os.Stat(p)
		if err != nil {
			states[p] = fileState{exists: false}
			continue
		}
		states[p] = fileState{exists: true, modTime: fi.ModTime(), size: fi.Size()}
	}
	return states
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
