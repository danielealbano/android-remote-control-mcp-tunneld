package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	spoolQueue        = 5000
	spoolWindow       = 5 * time.Minute
	spoolMaxFile      = 16 << 20
	spoolMaxBytes     = 1 << 30
	spoolRetry        = time.Minute
	spoolTick         = time.Second
	spoolIOLogEvery   = time.Minute
	spoolLockName     = ".lock"
	spoolReadySuffix  = ".jsonl"
	spoolActiveSuffix = ".jsonl.part"
	spoolMaxNameTries = 1000
)

var spoolName = regexp.MustCompile(`^(\d{8}T\d{6}\.\d{9}Z)-([0-9a-f]+)\.jsonl(\.part)?$`)

var nodeIDPattern = regexp.MustCompile(`^[0-9a-f]+$`)

type ConnLogUploader interface {
	PutConnLogFile(ctx context.Context, key string, body io.ReadSeeker, size int64) error
}

type ConnLogSpool struct {
	dir      string
	nodeID   string
	up       ConnLogUploader
	onDrop   func(n int)
	logger   *slog.Logger
	now      func() time.Time
	tick     time.Duration
	retry    time.Duration
	maxFile  int64
	maxBytes int64

	writeFile    func(f *os.File, b []byte) (int, error)
	syncFile     func(f *os.File) error
	truncateFile func(f *os.File, size int64) error

	lock *os.File

	mu     sync.RWMutex
	closed bool
	events chan Event

	spooled atomic.Int64

	ioMu         sync.Mutex
	ioLast       time.Time
	ioSuppressed int

	capWarned time.Time
	lastStart time.Time

	kick         chan struct{}
	stopUp       chan struct{}
	upCtx        context.Context
	upCancel     context.CancelFunc
	writerDone   chan struct{}
	uploaderDone chan struct{}
	drainOnce    sync.Once
}

type SpoolOption func(*ConnLogSpool) error

func WithSpoolClock(now func() time.Time) SpoolOption {
	return func(s *ConnLogSpool) error {
		if now == nil {
			return errors.New("store: nil conn-log spool clock")
		}
		s.now = now
		return nil
	}
}

func WithSpoolTick(d time.Duration) SpoolOption {
	return func(s *ConnLogSpool) error {
		if d <= 0 {
			return fmt.Errorf("store: non-positive conn-log spool tick %v", d)
		}
		s.tick = d
		return nil
	}
}

func WithSpoolRetry(d time.Duration) SpoolOption {
	return func(s *ConnLogSpool) error {
		if d <= 0 {
			return fmt.Errorf("store: non-positive conn-log upload retry %v", d)
		}
		s.retry = d
		return nil
	}
}

func WithSpoolLimits(maxFile, maxBytes int64) SpoolOption {
	return func(s *ConnLogSpool) error {
		if maxFile <= 0 || maxBytes <= 0 {
			return fmt.Errorf("store: non-positive conn-log spool limits %d / %d", maxFile, maxBytes)
		}
		s.maxFile, s.maxBytes = maxFile, maxBytes
		return nil
	}
}

func withFileOps(write func(*os.File, []byte) (int, error), sync func(*os.File) error, truncate func(*os.File, int64) error) SpoolOption {
	return func(s *ConnLogSpool) error {
		if write == nil || sync == nil || truncate == nil {
			return errors.New("store: nil conn-log spool file op")
		}
		s.writeFile, s.syncFile, s.truncateFile = write, sync, truncate
		return nil
	}
}

func NewConnLogSpool(dir, nodeID string, up ConnLogUploader, onDrop func(n int), logger *slog.Logger, opts ...SpoolOption) (*ConnLogSpool, error) {
	switch {
	case dir == "":
		return nil, errors.New("store: empty conn-log spool directory")
	case !nodeIDPattern.MatchString(nodeID):
		return nil, fmt.Errorf("store: conn-log node id %q must be lowercase hex", nodeID)
	case up == nil:
		return nil, errors.New("store: nil conn-log uploader")
	case onDrop == nil:
		return nil, errors.New("store: nil conn-log drop counter")
	case logger == nil:
		return nil, errors.New("store: nil conn-log logger")
	}
	s := &ConnLogSpool{
		dir: dir, nodeID: nodeID, up: up, onDrop: onDrop, logger: logger,
		now: time.Now, tick: spoolTick, retry: spoolRetry, maxFile: spoolMaxFile, maxBytes: spoolMaxBytes,
		writeFile: (*os.File).Write, syncFile: (*os.File).Sync, truncateFile: (*os.File).Truncate,
		events: make(chan Event, spoolQueue), kick: make(chan struct{}, 1), stopUp: make(chan struct{}),
		writerDone: make(chan struct{}), uploaderDone: make(chan struct{}),
	}
	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create conn-log spool directory: %w", err)
	}
	lock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	if err := s.recoverSpool(); err != nil {
		s.releaseLock()
		return nil, err
	}
	s.upCtx, s.upCancel = context.WithCancel(context.Background())
	go s.writer()
	go s.uploader()
	s.signalUpload()
	return s, nil
}

func lockDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, spoolLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open conn-log spool lock: %w", err)
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("store: conn-log spool lock fd: %w", err), f.Close())
	}
	var lockErr error
	if err := raw.Control(func(fd uintptr) {
		lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
	}); err != nil {
		return nil, errors.Join(fmt.Errorf("store: conn-log spool lock fd: %w", err), f.Close())
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return nil, errors.Join(fmt.Errorf("store: conn-log spool directory %s is in use by another process", dir), f.Close())
	}
	if lockErr != nil {
		return nil, errors.Join(fmt.Errorf("store: lock conn-log spool directory: %w", lockErr), f.Close())
	}
	return f, nil
}

func (s *ConnLogSpool) releaseLock() {
	if err := s.lock.Close(); err != nil {
		s.logger.Warn("conn-log spool lock release failed", "dir", s.dir, "err", err)
	}
}

func (s *ConnLogSpool) recoverSpool() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("store: list conn-log spool directory: %w", err)
	}
	for _, e := range entries {
		m := spoolName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(s.dir, e.Name())
		if m[3] == "" {
			info, err := e.Info()
			if err != nil {
				s.ioWarn("stat", path, err)
				continue
			}
			s.spooled.Add(info.Size())
			continue
		}
		s.recoverPart(path)
	}
	return nil
}

func (s *ConnLogSpool) recoverPart(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		s.ioWarn("read", path, err)
		return
	}
	keep := bytes.LastIndexByte(data, '\n') + 1
	if dropped := len(data) - keep; dropped > 0 {
		s.logger.Warn("conn-log spool recovered a torn last line (dropped)", "file", path, "bytes", dropped)
	}
	if keep == 0 {
		if err := os.Remove(path); err != nil {
			s.ioWarn("remove", path, err)
		}
		return
	}
	if keep < len(data) {
		if err := os.Truncate(path, int64(keep)); err != nil {
			s.ioWarn("truncate", path, err)
			return
		}
	}
	if err := os.Rename(path, strings.TrimSuffix(path, ".part")); err != nil {
		s.ioWarn("rename", path, err)
		return
	}
	s.spooled.Add(int64(keep))
}

// PutConnLog enqueues (drop-newest on a full queue). Always returns nil: delivery is the workers' job.
func (s *ConnLogSpool) PutConnLog(_ context.Context, ev Event) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.onDrop(1)
		return nil
	}
	select {
	case s.events <- ev:
	default:
		s.onDrop(1)
	}
	return nil
}

type activeFile struct {
	f        *os.File
	path     string
	size     int64
	winStart time.Time
}

func (s *ConnLogSpool) writer() {
	defer close(s.writerDone)
	t := time.NewTicker(s.tick)
	defer t.Stop()
	var w activeFile
	for {
		select {
		case ev, ok := <-s.events:
			if !ok {
				s.rotate(&w)
				return
			}
			s.append(&w, ev)
		case <-t.C:
			if w.f != nil && !s.inWindow(w, s.now()) {
				s.rotate(&w)
			}
		}
	}
}

func (s *ConnLogSpool) inWindow(w activeFile, now time.Time) bool {
	now = now.UTC()
	return !now.Before(w.winStart) && now.Before(w.winStart.Add(spoolWindow))
}

func (s *ConnLogSpool) append(w *activeFile, ev Event) {
	line, err := json.Marshal(ev)
	if err != nil {
		s.onDrop(1)
		s.ioWarn("encode", s.dir, err)
		return
	}
	line = append(line, '\n')
	now := s.now()
	if w.f != nil && !s.inWindow(*w, now) {
		s.rotate(w)
	}
	if s.spooled.Load()+int64(len(line)) > s.maxBytes {
		s.onDrop(1)
		s.capWarn(now)
		return
	}
	if w.f == nil {
		if err := s.open(w, now); err != nil {
			s.onDrop(1)
			s.ioWarn("create", s.dir, err)
			return
		}
	}
	n, err := s.writeFile(w.f, line)
	if err != nil {
		s.onDrop(1)
		s.ioWarn("append", w.path, err)
		if terr := s.truncateFile(w.f, w.size); terr != nil {
			s.ioWarn("truncate", w.path, terr)
			s.spooled.Add(int64(n))
			w.size += int64(n)
			s.rotate(w)
		}
		return
	}
	w.size += int64(n)
	s.spooled.Add(int64(n))
	if w.size >= s.maxFile {
		s.rotate(w)
	}
}

func (s *ConnLogSpool) open(w *activeFile, now time.Time) error {
	now = now.UTC()
	start := now
	if !start.After(s.lastStart) {
		start = s.lastStart.Add(time.Nanosecond)
	}
	for range spoolMaxNameTries {
		base := start.Format(tsNanosLayout) + "-" + s.nodeID
		ready := filepath.Join(s.dir, base+spoolReadySuffix)
		if _, err := os.Lstat(ready); err == nil {
			start = start.Add(time.Nanosecond)
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		path := filepath.Join(s.dir, base+spoolActiveSuffix)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if errors.Is(err, fs.ErrExist) {
			start = start.Add(time.Nanosecond)
			continue
		}
		if err != nil {
			return err
		}
		*w = activeFile{f: f, path: path, winStart: now.Truncate(spoolWindow)}
		s.lastStart = start
		return nil
	}
	return fmt.Errorf("no free conn-log spool file name after %d tries", spoolMaxNameTries)
}

func (s *ConnLogSpool) rotate(w *activeFile) {
	if w.f == nil {
		return
	}
	if err := s.syncFile(w.f); err != nil {
		s.ioWarn("fsync", w.path, err)
	}
	if err := w.f.Close(); err != nil {
		s.ioWarn("close", w.path, err)
	}
	if err := os.Rename(w.path, strings.TrimSuffix(w.path, ".part")); err != nil {
		s.ioWarn("rename", w.path, err)
	} else {
		s.signalUpload()
	}
	*w = activeFile{}
}

func (s *ConnLogSpool) signalUpload() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *ConnLogSpool) uploader() {
	defer close(s.uploaderDone)
	t := time.NewTicker(s.retry)
	defer t.Stop()
	for {
		select {
		case <-s.kick:
			s.pass()
		case <-t.C:
			s.pass()
		case <-s.stopUp:
			for !s.pass() && s.upCtx.Err() == nil {
				select {
				case <-time.After(s.retry):
				case <-s.upCtx.Done():
				}
			}
			return
		}
	}
}

func (s *ConnLogSpool) readyFiles() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if m := spoolName.FindStringSubmatch(e.Name()); m != nil && m[3] == "" && e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (s *ConnLogSpool) pass() bool {
	names, err := s.readyFiles()
	if err != nil {
		s.ioWarn("list", s.dir, err)
		return false
	}
	clean := true
	for _, name := range names {
		if s.upCtx.Err() != nil {
			return false
		}
		uploaded, failed := s.uploadFile(name)
		if failed {
			return false
		}
		if !uploaded {
			clean = false
		}
	}
	return clean
}

func (s *ConnLogSpool) uploadFile(name string) (uploaded, failed bool) {
	path := filepath.Join(s.dir, name)
	key, err := spoolKey(name)
	if err != nil {
		s.ioWarn("key", path, err)
		return false, false
	}
	f, err := os.Open(path)
	if err != nil {
		s.ioWarn("open", path, err)
		return false, false
	}
	info, err := f.Stat()
	if err != nil {
		s.ioWarn("stat", path, errors.Join(err, f.Close()))
		return false, false
	}
	err = s.up.PutConnLogFile(s.upCtx, key, f, info.Size())
	if cerr := f.Close(); cerr != nil {
		s.ioWarn("close", path, cerr)
	}
	if err != nil {
		if s.upCtx.Err() == nil {
			s.logger.Warn("conn-log upload failed (will retry)", "file", path, "err", err)
		}
		return false, true
	}
	if err := os.Remove(path); err != nil {
		s.ioWarn("remove", path, err)
		return false, false
	}
	s.spooled.Add(-info.Size())
	return true, false
}

func spoolKey(name string) (string, error) {
	m := spoolName.FindStringSubmatch(name)
	if m == nil || m[3] != "" {
		return "", fmt.Errorf("not a ready conn-log spool file: %q", name)
	}
	ts, err := time.Parse(tsNanosLayout, m[1])
	if err != nil {
		return "", fmt.Errorf("conn-log spool file %q: %w", name, err)
	}
	return fmt.Sprintf("tunnel-logs/%04d/%02d/%02d/%s", ts.Year(), ts.Month(), ts.Day(), name), nil
}

func (s *ConnLogSpool) capWarn(now time.Time) {
	win := now.UTC().Truncate(spoolWindow)
	if win.Equal(s.capWarned) {
		return
	}
	s.capWarned = win
	s.logger.Warn("conn-log spool full (dropping new events until uploads catch up)",
		"dir", s.dir, "cap_bytes", s.maxBytes, "spooled_bytes", s.spooled.Load())
}

func (s *ConnLogSpool) ioWarn(op, path string, err error) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	now := s.now()
	if !s.ioLast.IsZero() && now.Sub(s.ioLast) < spoolIOLogEvery {
		s.ioSuppressed++
		return
	}
	s.logger.Warn("conn-log spool I/O failed", "op", op, "path", path, "err", err, "suppressed_since_last", s.ioSuppressed)
	s.ioLast, s.ioSuppressed = now, 0
}

// Drain stops intake and waits for the queue to flush or ctx to expire (server shutdown).
func (s *ConnLogSpool) Drain(ctx context.Context) {
	s.drainOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.events)
		s.mu.Unlock()
		stop := context.AfterFunc(ctx, s.upCancel)
		defer stop()
		select {
		case <-s.writerDone:
		case <-ctx.Done():
			s.logger.Warn("conn-log spool writer did not finish by the shutdown deadline", "dir", s.dir)
		}
		close(s.stopUp)
		<-s.uploaderDone
		s.upCancel()
		if names, err := s.readyFiles(); err != nil {
			s.ioWarn("list", s.dir, err)
		} else if len(names) > 0 {
			s.logger.Warn("conn-log spool files left for the next start", "dir", s.dir, "files", len(names))
		}
		s.releaseLock()
	})
}
