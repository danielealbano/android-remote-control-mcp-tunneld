package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/report"
)

const (
	PhonesSeenPrefix = "phones-seen/"

	phonesSeenTick          = time.Minute
	phonesSeenDebounce      = time.Second
	phonesSeenUploadEvery   = 15 * time.Minute
	phonesSeenUploadTimeout = 30 * time.Second
	phonesSeenWarnEvery     = time.Minute
	phonesSeenFileDay       = "20060102"
	phonesSeenDay           = "2006-01-02"
)

var (
	phonesSeenName = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})-([0-9a-f]+)\.json$`)
	phonesSeenTemp = regexp.MustCompile(`^\d{8}-[0-9a-f]+\.json\.tmp$`)
)

type PhonesSeenFile struct {
	Schema int                  `json:"schema"`
	Node   string               `json:"node"`
	Day    string               `json:"day"`
	Phones map[string]PhoneSeen `json:"phones"`
}

type PhoneSeen struct {
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

type PhonesSeenUploader interface {
	PutPhonesSeenFile(ctx context.Context, key string, body io.ReadSeeker, size int64) error
}

type PhonesSeen struct {
	dir      string
	nodeID   string
	up       PhonesSeenUploader
	logger   *slog.Logger
	now      func() time.Time
	tick     time.Duration
	debounce time.Duration
	saveFile func(path string, data []byte) error
	remove   func(path string) error
	readDir  func(dir string) ([]os.DirEntry, error)

	lock   *os.File
	fileMu sync.Mutex
	saves  map[string]uint64

	mu     sync.Mutex
	day    time.Time
	phones map[string]PhoneSeen
	live   map[string]int
	dirty  bool
	ended  []PhonesSeenFile

	uploadedName string
	uploadedSlot time.Time

	warnMu         sync.Mutex
	warnLast       time.Time
	warnSuppressed int
	warnLastMsg    string
	warnLastErr    error

	kick         chan struct{}
	stop         chan struct{}
	saverDone    chan struct{}
	uploaderDone chan struct{}
	upCtx        context.Context
	upCancel     context.CancelFunc
	drainOnce    sync.Once
}

type phonesSeenOption func(*PhonesSeen) error

func withPhonesSeenClock(now func() time.Time) phonesSeenOption {
	return func(p *PhonesSeen) error {
		if now == nil {
			return errors.New("store: nil phones-seen clock")
		}
		p.now = now
		return nil
	}
}

func withPhonesSeenTicks(tick, debounce time.Duration) phonesSeenOption {
	return func(p *PhonesSeen) error {
		if tick <= 0 || debounce <= 0 {
			return fmt.Errorf("store: non-positive phones-seen tick %v / debounce %v", tick, debounce)
		}
		p.tick, p.debounce = tick, debounce
		return nil
	}
}

func withPhonesSeenFileOps(save func(path string, data []byte) error, remove func(path string) error, readDir func(dir string) ([]os.DirEntry, error)) phonesSeenOption {
	return func(p *PhonesSeen) error {
		if save == nil || remove == nil || readDir == nil {
			return errors.New("store: nil phones-seen file op")
		}
		p.saveFile, p.remove, p.readDir = save, remove, readDir
		return nil
	}
}

func NewPhonesSeen(ctx context.Context, dir, nodeID string, up PhonesSeenUploader, logger *slog.Logger, opts ...phonesSeenOption) (*PhonesSeen, error) {
	switch {
	case dir == "":
		return nil, errors.New("store: empty phones-seen directory")
	case !nodeIDPattern.MatchString(nodeID):
		return nil, fmt.Errorf("store: phones-seen node id %q must be lowercase hex", nodeID)
	case up == nil:
		return nil, errors.New("store: nil phones-seen uploader")
	case logger == nil:
		return nil, errors.New("store: nil phones-seen logger")
	}
	p := &PhonesSeen{
		dir: dir, nodeID: nodeID, up: up, logger: logger, now: time.Now, tick: phonesSeenTick, debounce: phonesSeenDebounce,
		saveFile: saveFileSynced, remove: os.Remove, readDir: os.ReadDir,
		phones: map[string]PhoneSeen{}, live: map[string]int{}, saves: map[string]uint64{},
		kick: make(chan struct{}, 1), stop: make(chan struct{}), saverDone: make(chan struct{}), uploaderDone: make(chan struct{}),
	}
	for _, o := range opts {
		if err := o(p); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create phones-seen directory: %w", err)
	}
	lock, err := lockDir(dir, "phones-seen")
	if err != nil {
		return nil, err
	}
	p.lock = lock
	p.removeTemps()
	p.day = utcDay(p.now())
	p.upCtx, p.upCancel = context.WithCancel(context.WithoutCancel(ctx))
	go func() {
		defer report.Crash(p.upCtx, p.logger, "phones-seen saver")
		p.saver()
	}()
	go func() {
		defer report.Crash(p.upCtx, p.logger, "phones-seen uploader")
		p.uploader()
	}()
	return p, nil
}

func saveFileSynced(path string, data []byte) error {
	tmp := path + ".tmp"
	w, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := w.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", tmp, err), w.Close())
	}
	if err := w.Sync(); err != nil {
		return errors.Join(fmt.Errorf("flush %s to disk: %w", tmp, err), w.Close())
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

func (p *PhonesSeen) removeTemps() {
	entries, err := p.readDir(p.dir)
	if err != nil {
		p.logger.Warn("could not look for unfinished lists of phones seen left from an earlier run; any that are left stay on disk", "dir", p.dir, "err", err)
		return
	}
	for _, e := range entries {
		if !phonesSeenTemp.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(p.dir, e.Name())
		if err := p.remove(path); err != nil {
			p.logger.Warn("could not remove an unfinished list of phones seen left from an earlier run; it stays on disk", "file", path, "err", err)
		}
	}
}

func utcDay(t time.Time) time.Time {
	return t.UTC().Truncate(24 * time.Hour)
}

func (p *PhonesSeen) PhoneOpen(name string)  { p.touch(name, 1) }
func (p *PhonesSeen) PhoneClose(name string) { p.touch(name, -1) }

func (p *PhonesSeen) touch(name string, delta int) {
	now := p.now().UTC()
	p.mu.Lock()
	p.rollLocked(now)
	if n := p.live[name] + delta; n > 0 {
		p.live[name] = n
	} else {
		delete(p.live, name)
	}
	p.seenLocked(name, now)
	p.mu.Unlock()
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *PhonesSeen) seenLocked(name string, at time.Time) {
	s, ok := p.phones[name]
	if !ok {
		s.First = at
	}
	if at.After(s.Last) {
		s.Last = at
	}
	p.phones[name] = s
	p.dirty = true
}

func (p *PhonesSeen) rollLocked(now time.Time) {
	day := utcDay(now)
	if !day.After(p.day) {
		return
	}
	end := p.day.Add(24*time.Hour - time.Nanosecond)
	for name := range p.live {
		p.seenLocked(name, end)
	}
	if p.dirty {
		p.ended = append(p.ended, p.fileLocked())
	}
	p.day, p.phones = day, map[string]PhoneSeen{}
	for name := range p.live {
		p.phones[name] = PhoneSeen{First: day, Last: day}
	}
	p.dirty = len(p.live) > 0
}

func (p *PhonesSeen) saver() {
	defer close(p.saverDone)
	t := time.NewTicker(p.tick)
	defer t.Stop()
	var pending <-chan time.Time
	for {
		select {
		case <-p.kick:
			if pending == nil {
				pending = time.After(p.debounce)
			}
		case <-pending:
			pending = nil
			p.save(false)
		case <-t.C:
			p.save(false)
			p.flushWarns(false)
		case <-p.stop:
			return
		}
	}
}

func (p *PhonesSeen) uploader() {
	defer close(p.uploaderDone)
	t := time.NewTicker(p.tick)
	defer t.Stop()
	p.upload(false)
	for {
		select {
		case <-t.C:
			p.upload(false)
		case <-p.stop:
			return
		}
	}
}

func (p *PhonesSeen) save(final bool) {
	ended, current := p.snapshot(p.now().UTC())
	for _, f := range ended {
		if err := p.writeLocal(f); err != nil {
			p.problem(final, "could not save the list of phones seen on a day that has ended; it is tried again within a minute",
				"could not save the list of phones seen on a day that has ended before stopping, so what changed since its last save is lost",
				err, "day", f.Day, "dir", p.dir)
			p.retry(f)
		}
	}
	if current != nil {
		if err := p.writeLocal(*current); err != nil {
			p.problem(final, "could not save the list of phones seen today; it is tried again within a minute",
				"could not save the list of phones seen today before stopping, so what changed since its last save is lost",
				err, "day", current.Day, "dir", p.dir)
			p.retry(*current)
		}
	}
}

func (p *PhonesSeen) retry(f PhonesSeenFile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f.Day == p.day.Format(phonesSeenDay) {
		p.dirty = true
		return
	}
	for _, queued := range p.ended {
		if queued.Day == f.Day {
			return
		}
	}
	p.ended = append(p.ended, f)
}

func (p *PhonesSeen) snapshot(now time.Time) ([]PhonesSeenFile, *PhonesSeenFile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rollLocked(now)
	for name := range p.live {
		p.seenLocked(name, now)
	}
	ended := p.ended
	p.ended = nil
	var current *PhonesSeenFile
	if p.dirty {
		f := p.fileLocked()
		current = &f
		p.dirty = false
	}
	return ended, current
}

func (p *PhonesSeen) fileLocked() PhonesSeenFile {
	return PhonesSeenFile{Schema: 1, Node: p.nodeID, Day: p.day.Format(phonesSeenDay), Phones: maps.Clone(p.phones)}
}

func phonesSeenFileName(day time.Time, nodeID string) string {
	return day.Format(phonesSeenFileDay) + "-" + nodeID + ".json"
}

func (p *PhonesSeen) writeLocal(f PhonesSeenFile) error {
	day, err := time.Parse(phonesSeenDay, f.Day)
	if err != nil {
		return fmt.Errorf("read the day %q of the list: %w", f.Day, err)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode the list of %s: %w", f.Day, err)
	}
	name := phonesSeenFileName(day, f.Node)
	p.fileMu.Lock()
	defer p.fileMu.Unlock()
	if err := p.saveFile(filepath.Join(p.dir, name), data); err != nil {
		return err
	}
	p.saves[name]++
	return nil
}

func (p *PhonesSeen) currentName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return phonesSeenFileName(p.day, p.nodeID)
}

func (p *PhonesSeen) upload(final bool) {
	entries, err := p.readDir(p.dir)
	if err != nil {
		p.problem(final, "could not list the saved lists of phones seen to upload them; it is tried again within a minute",
			"could not list the saved lists of phones seen to upload them before stopping; they are uploaded after the next start", err, "dir", p.dir)
		return
	}
	currentName := p.currentName()
	slot := p.now().UTC().Truncate(phonesSeenUploadEvery)
	var errs []error
	for _, e := range entries {
		m := phonesSeenName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		isCurrent := e.Name() == currentName
		if isCurrent && !final && e.Name() == p.uploadedName && !slot.After(p.uploadedSlot) {
			continue
		}
		path := filepath.Join(p.dir, e.Name())
		key := fmt.Sprintf("%s%s/%s/%s/%s.json", PhonesSeenPrefix, m[1], m[2], m[3], m[4])
		saves := p.savesOf(e.Name())
		if err := p.put(path, key); err != nil {
			errs = append(errs, err)
			continue
		}
		if isCurrent {
			p.uploadedName, p.uploadedSlot = e.Name(), slot
			continue
		}
		if err := p.removeUploaded(e.Name(), saves); err != nil {
			p.problem(final, "could not remove an uploaded list of phones seen; it is uploaded again within a minute, replacing the same object",
				"could not remove an uploaded list of phones seen before stopping; it is uploaded again after the next start, replacing the same object",
				err, "file", path)
		}
	}
	if len(errs) > 0 && (final || p.upCtx.Err() == nil) {
		p.problem(final, "could not upload the lists of phones seen; they stay on disk and are tried again within a minute",
			"could not upload the lists of phones seen before stopping; they stay on disk and are uploaded after the next start", errors.Join(errs...), "files", len(errs))
	}
}

func (p *PhonesSeen) savesOf(name string) uint64 {
	p.fileMu.Lock()
	defer p.fileMu.Unlock()
	return p.saves[name]
}

func (p *PhonesSeen) removeUploaded(name string, savesAtUpload uint64) error {
	p.fileMu.Lock()
	defer p.fileMu.Unlock()
	if p.saves[name] != savesAtUpload {
		return nil
	}
	if err := p.remove(filepath.Join(p.dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	delete(p.saves, name)
	return nil
}

func (p *PhonesSeen) put(path, key string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			p.warn("could not close a list of phones seen after uploading it; the upload result is not affected", cerr, "file", path)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("read the size of %s: %w", path, err)
	}
	uctx, cancel := context.WithTimeout(p.upCtx, phonesSeenUploadTimeout)
	defer cancel()
	if err := p.up.PutPhonesSeenFile(uctx, key, f, info.Size()); err != nil {
		return fmt.Errorf("upload %s: %w", key, err)
	}
	return nil
}

func (p *PhonesSeen) problem(final bool, msg, finalMsg string, err error, args ...any) {
	if final {
		p.logger.Warn(finalMsg, append(args, "err", err)...)
		return
	}
	p.warn(msg, err, args...)
}

func (p *PhonesSeen) warn(msg string, err error, args ...any) {
	p.warnMu.Lock()
	defer p.warnMu.Unlock()
	now := p.now()
	if !p.warnLast.IsZero() && now.Sub(p.warnLast) < phonesSeenWarnEvery {
		p.warnSuppressed++
		p.warnLastMsg, p.warnLastErr = msg, err
		return
	}
	p.logger.Warn(msg, append(args, "err", err, "suppressed_since_last", p.warnSuppressed)...)
	p.warnLast, p.warnSuppressed = now, 0
}

func (p *PhonesSeen) flushWarns(force bool) {
	p.warnMu.Lock()
	defer p.warnMu.Unlock()
	if p.warnSuppressed == 0 || !force && p.now().Sub(p.warnLast) < phonesSeenWarnEvery {
		return
	}
	p.logger.Warn("more errors with the lists of phones seen happened and were not logged one by one", "count", p.warnSuppressed,
		"last_msg", p.warnLastMsg, "last_err", p.warnLastErr)
	p.warnLast, p.warnSuppressed = p.now(), 0
}

func (p *PhonesSeen) Drain(ctx context.Context) {
	p.drainOnce.Do(func() {
		stop := context.AfterFunc(ctx, p.upCancel)
		defer stop()
		close(p.stop)
		<-p.saverDone
		<-p.uploaderDone
		p.save(true)
		p.upload(true)
		p.upCancel()
		p.flushWarns(true)
		if err := p.lock.Close(); err != nil {
			p.logger.Warn("could not release the phones-seen directory lock cleanly; the system releases it at the latest when tunneld exits", "dir", p.dir, "err", err)
		}
	})
}
