package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	lock *os.File

	mu     sync.Mutex
	day    time.Time
	phones map[string]PhoneSeen
	live   map[string]int
	dirty  bool
	ended  []PhonesSeenFile

	uploadedSlot time.Time

	kick      chan struct{}
	stop      chan struct{}
	done      chan struct{}
	upCtx     context.Context
	upCancel  context.CancelFunc
	drainOnce sync.Once
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
		phones: map[string]PhoneSeen{}, live: map[string]int{},
		kick: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
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
		defer report.Crash(p.upCtx, p.logger, "phones-seen writer")
		p.loop()
	}()
	return p, nil
}

func (p *PhonesSeen) removeTemps() {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		p.logger.Warn("could not look for unfinished lists of phones seen left from an earlier run; any that are left stay on disk", "dir", p.dir, "err", err)
		return
	}
	for _, e := range entries {
		if !phonesSeenTemp.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(p.dir, e.Name())
		if err := os.Remove(path); err != nil {
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

func (p *PhonesSeen) loop() {
	defer close(p.done)
	t := time.NewTicker(p.tick)
	defer t.Stop()
	var pending <-chan time.Time
	p.flush(false)
	for {
		select {
		case <-p.kick:
			if pending == nil {
				pending = time.After(p.debounce)
			}
		case <-pending:
			pending = nil
			p.flush(false)
		case <-t.C:
			p.flush(false)
		case <-p.stop:
			return
		}
	}
}

func (p *PhonesSeen) flush(final bool) bool {
	now := p.now().UTC()
	ended, current, currentName := p.snapshot(now)
	clean := true
	for _, f := range ended {
		if err := p.writeLocal(f); err != nil {
			p.logger.Warn("could not save the list of phones seen on a day that has ended; it is tried again within a minute", "day", f.Day, "dir", p.dir, "err", err)
			p.mu.Lock()
			p.ended = append(p.ended, f)
			p.mu.Unlock()
			clean = false
		}
	}
	if current != nil {
		if err := p.writeLocal(*current); err != nil {
			p.logger.Warn("could not save the list of phones seen today; it is tried again within a minute", "day", current.Day, "dir", p.dir, "err", err)
			p.mu.Lock()
			p.dirty = true
			p.mu.Unlock()
			clean = false
		}
	}
	return p.upload(now, currentName, final) && clean
}

func (p *PhonesSeen) snapshot(now time.Time) ([]PhonesSeenFile, *PhonesSeenFile, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if day := utcDay(now); day.After(p.day) {
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
	return ended, current, phonesSeenFileName(p.day, p.nodeID)
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
		return err
	}
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	path := filepath.Join(p.dir, phonesSeenFileName(day, f.Node))
	tmp := path + ".tmp"
	w, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return errors.Join(err, w.Close())
	}
	if err := w.Sync(); err != nil {
		return errors.Join(err, w.Close())
	}
	if err := w.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (p *PhonesSeen) upload(now time.Time, currentName string, final bool) bool {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		p.logger.Warn("could not list the saved lists of phones seen to upload them; it is tried again within a minute", "dir", p.dir, "err", err)
		return false
	}
	slot := now.Truncate(phonesSeenUploadEvery)
	var (
		failed  int
		lastErr error
	)
	for _, e := range entries {
		m := phonesSeenName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		isCurrent := e.Name() == currentName
		if isCurrent && !final && !slot.After(p.uploadedSlot) {
			continue
		}
		path := filepath.Join(p.dir, e.Name())
		key := fmt.Sprintf("%s%s/%s/%s/%s.json", PhonesSeenPrefix, m[1], m[2], m[3], m[4])
		if err := p.put(path, key); err != nil {
			failed++
			lastErr = err
			continue
		}
		if isCurrent {
			p.uploadedSlot = slot
			continue
		}
		if err := os.Remove(path); err != nil {
			p.logger.Warn("could not remove an uploaded list of phones seen; it is uploaded again within a minute, replacing the same object", "file", path, "err", err)
			failed++
		}
	}
	if lastErr != nil && p.upCtx.Err() == nil {
		p.logger.Warn("could not upload the lists of phones seen; they stay on disk and are tried again within a minute", "files", failed, "err", lastErr)
	}
	return failed == 0
}

func (p *PhonesSeen) put(path, key string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			p.logger.Warn("could not close a list of phones seen after uploading it; the upload result is not affected", "file", path, "err", cerr)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	uctx, cancel := context.WithTimeout(p.upCtx, phonesSeenUploadTimeout)
	defer cancel()
	return p.up.PutPhonesSeenFile(uctx, key, f, info.Size())
}

func (p *PhonesSeen) Drain(ctx context.Context) {
	p.drainOnce.Do(func() {
		close(p.stop)
		<-p.done
		stop := context.AfterFunc(ctx, p.upCancel)
		defer stop()
		if !p.flush(true) {
			p.logger.Warn("could not save or upload every list of phones seen before stopping; what is on disk is uploaded after the next start", "dir", p.dir)
		}
		p.upCancel()
		if err := p.lock.Close(); err != nil {
			p.logger.Warn("could not release the phones-seen directory lock cleanly; the system releases it at the latest when tunneld exits", "dir", p.dir, "err", err)
		}
	})
}
