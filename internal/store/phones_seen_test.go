package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeSeenUploader struct {
	mu       sync.Mutex
	puts     map[string][]PhonesSeenFile
	err      error
	block    bool
	inFlight chan struct{}
}

func newFakeSeenUploader() *fakeSeenUploader {
	return &fakeSeenUploader{puts: map[string][]PhonesSeenFile{}, inFlight: make(chan struct{}, 1)}
}

func (f *fakeSeenUploader) PutPhonesSeenFile(ctx context.Context, key string, body io.ReadSeeker, size int64) error {
	f.mu.Lock()
	block := f.block
	f.mu.Unlock()
	if block {
		select {
		case f.inFlight <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if int64(len(raw)) != size {
		return fmt.Errorf("size %d, body %d bytes", size, len(raw))
	}
	var pf PhonesSeenFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.puts[key] = append(f.puts[key], pf)
	return nil
}

func (f *fakeSeenUploader) versions(key string) []PhonesSeenFile {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PhonesSeenFile(nil), f.puts[key]...)
}

func (f *fakeSeenUploader) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

type seenFS struct {
	mu        sync.Mutex
	saveErr   func(path string) error
	removeErr func(path string) error
}

func (s *seenFS) save(path string, data []byte) error {
	s.mu.Lock()
	fail := s.saveErr
	s.mu.Unlock()
	if fail != nil {
		if err := fail(path); err != nil {
			return err
		}
	}
	return saveFileSynced(path, data)
}

func (s *seenFS) rm(path string) error {
	s.mu.Lock()
	fail := s.removeErr
	s.mu.Unlock()
	if fail != nil {
		if err := fail(path); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func (s *seenFS) set(saveErr, removeErr func(path string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveErr, s.removeErr = saveErr, removeErr
}

func failAll(err error) func(string) error { return func(string) error { return err } }

func failSuffix(suffix string, err error) func(string) error {
	return func(path string) error {
		if strings.HasSuffix(path, suffix) {
			return err
		}
		return nil
	}
}

type seenEnv struct {
	p     *PhonesSeen
	dir   string
	clock *fakeClock
	up    *fakeSeenUploader
	fs    *seenFS
	log   *syncBuf
}

func stderrLogger() *slog.Logger { return slog.New(slog.NewTextHandler(os.Stderr, nil)) }

func newSeen(t *testing.T, dir string, at time.Time, up *fakeSeenUploader) seenEnv {
	t.Helper()
	return newSeenWithFS(t, dir, at, up, &seenFS{})
}

func newSeenWithFS(t *testing.T, dir string, at time.Time, up *fakeSeenUploader, fs *seenFS) seenEnv {
	t.Helper()
	clock := newClock(at)
	log := &syncBuf{}
	p, err := NewPhonesSeen(context.Background(), dir, testNode, up, slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, log), nil)),
		withPhonesSeenClock(clock.now), withPhonesSeenTicks(2*time.Millisecond, time.Millisecond), withPhonesSeenFileOps(fs.save, fs.rm))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { drainSeenWithin(p, 5*time.Second) })
	return seenEnv{p: p, dir: dir, clock: clock, up: up, fs: fs, log: log}
}

func drainSeenWithin(p *PhonesSeen, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	p.Drain(ctx)
}

func readSeenFile(t *testing.T, path string) (PhonesSeenFile, bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return PhonesSeenFile{}, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var f PhonesSeenFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("invalid phones-seen file %s: %v", path, err)
	}
	return f, true
}

func seenKey(day string) string {
	return PhonesSeenPrefix + day + "/" + testNode + ".json"
}

func localSeen(dir, day string) string {
	return filepath.Join(dir, day+"-"+testNode+".json")
}

func (e seenEnv) suppressed() int {
	e.p.warnMu.Lock()
	defer e.p.warnMu.Unlock()
	return e.p.warnSuppressed
}

func TestPhonesSeen_SavesEachPhoneAndUploadsOncePerQuarterHour(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC)
	env := newSeen(t, t.TempDir(), start, newFakeSeenUploader())
	local := localSeen(env.dir, "20261013")
	env.p.PhoneOpen("abc")
	waitFor(t, "the first upload", func() bool { return len(env.up.versions(seenKey("2026/10/13"))) == 1 })
	env.clock.set(start.Add(3 * time.Minute))
	env.p.PhoneClose("abc")
	waitFor(t, "the close on disk", func() bool {
		f, ok := readSeenFile(t, local)
		return ok && f.Phones["abc"].Last.Equal(start.Add(3*time.Minute))
	})
	f, _ := readSeenFile(t, local)
	want := PhoneSeen{First: start, Last: start.Add(3 * time.Minute)}
	if f.Schema != 1 || f.Node != testNode || f.Day != "2026-10-13" || len(f.Phones) != 1 || f.Phones["abc"] != want {
		t.Fatalf("the saved list must hold the phone's first and last time seen, got %+v", f)
	}
	time.Sleep(20 * time.Millisecond)
	if got := env.up.versions(seenKey("2026/10/13")); len(got) != 1 {
		t.Fatalf("today's list must be uploaded at most once per quarter hour, got %d uploads", len(got))
	}
	env.clock.set(time.Date(2026, 10, 13, 10, 15, 0, 0, time.UTC))
	waitFor(t, "the next quarter-hour upload", func() bool { return len(env.up.versions(seenKey("2026/10/13"))) == 2 })
	if got := env.up.versions(seenKey("2026/10/13"))[1].Phones["abc"]; got != want {
		t.Fatalf("the quarter-hour upload must carry the saved list, got %+v", got)
	}
	if _, err := os.Stat(local); err != nil {
		t.Fatalf("today's list must stay on disk after its upload: %v", err)
	}
}

func TestPhonesSeen_ConnectedPhoneLastSeenFollowsTheClock(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC)
	env := newSeen(t, t.TempDir(), start, newFakeSeenUploader())
	local := localSeen(env.dir, "20261013")
	env.p.PhoneOpen("abc")
	env.p.PhoneOpen("abc")
	env.p.PhoneClose("abc")
	later := start.Add(40 * time.Minute)
	env.clock.set(later)
	waitFor(t, "the refresh of the connected phone", func() bool {
		f, ok := readSeenFile(t, local)
		return ok && f.Phones["abc"].Last.Equal(later)
	})
	gone := later.Add(time.Minute)
	env.clock.set(gone)
	env.p.PhoneClose("abc")
	waitFor(t, "the last close", func() bool {
		f, ok := readSeenFile(t, local)
		return ok && f.Phones["abc"].Last.Equal(gone)
	})
	env.clock.set(gone.Add(time.Hour))
	time.Sleep(20 * time.Millisecond)
	if f, _ := readSeenFile(t, local); !f.Phones["abc"].Last.Equal(gone) || !f.Phones["abc"].First.Equal(start) {
		t.Fatalf("a phone with no connection left must keep its last time seen, got %+v", f.Phones["abc"])
	}
}

func TestPhonesSeen_DayRolloverEndsTheDayAndCarriesConnectedPhones(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 23, 50, 0, 0, time.UTC)
	env := newSeen(t, t.TempDir(), start, newFakeSeenUploader())
	env.p.PhoneOpen("abc")
	env.clock.set(start.Add(5 * time.Minute))
	env.p.PhoneOpen("def")
	env.p.PhoneClose("def")
	waitFor(t, "the first upload", func() bool { return len(env.up.versions(seenKey("2026/10/13"))) >= 1 })
	next := time.Date(2026, 10, 14, 0, 1, 0, 0, time.UTC)
	env.clock.set(next)
	endOfDay := time.Date(2026, 10, 13, 23, 59, 59, 999999999, time.UTC)
	waitFor(t, "the ended day's final upload and removal", func() bool {
		_, ok := readSeenFile(t, localSeen(env.dir, "20261013"))
		v := env.up.versions(seenKey("2026/10/13"))
		return !ok && len(v) > 0 && v[len(v)-1].Phones["abc"].Last.Equal(endOfDay) && len(env.up.versions(seenKey("2026/10/14"))) >= 1
	})
	ended := env.up.versions(seenKey("2026/10/13"))
	last := ended[len(ended)-1]
	if got := last.Phones["abc"].Last; !got.Equal(endOfDay) {
		t.Fatalf("a phone connected through midnight must be seen until the end of the day, got %v", got)
	}
	if got := last.Phones["def"].Last; !got.Equal(start.Add(5 * time.Minute)) {
		t.Fatalf("a phone gone before midnight must keep its last time seen, got %v", got)
	}
	today := env.up.versions(seenKey("2026/10/14"))[0]
	if _, ok := today.Phones["def"]; ok || len(today.Phones) != 1 {
		t.Fatalf("only the connected phone may carry over to the new day, got %+v", today.Phones)
	}
	if got := today.Phones["abc"]; !got.First.Equal(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)) || !got.Last.Equal(next) {
		t.Fatalf("the connected phone must be seen from midnight on, got %+v", got)
	}
}

func TestPhonesSeen_RolloverAcrossSkippedDaysEndsTheOldDay(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 22, 0, 0, 0, time.UTC)
	env := newSeen(t, t.TempDir(), start, newFakeSeenUploader())
	env.p.PhoneOpen("abc")
	waitFor(t, "the first upload", func() bool { return len(env.up.versions(seenKey("2026/10/13"))) == 1 })
	env.clock.set(time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC))
	waitFor(t, "the new day's upload", func() bool { return len(env.up.versions(seenKey("2026/10/16"))) >= 1 })
	waitFor(t, "the ended day's final upload", func() bool {
		v := env.up.versions(seenKey("2026/10/13"))
		return len(v) >= 2 && v[len(v)-1].Phones["abc"].Last.Equal(time.Date(2026, 10, 13, 23, 59, 59, 999999999, time.UTC))
	})
	for _, day := range []string{"2026/10/14", "2026/10/15"} {
		if got := env.up.versions(seenKey(day)); len(got) != 0 {
			t.Fatalf("no list may be written for a skipped day %s, got %+v", day, got)
		}
	}
	if got := env.up.versions(seenKey("2026/10/16"))[0].Phones["abc"].First; !got.Equal(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("the connected phone must start the current day at its midnight, got %v", got)
	}
}

func TestPhonesSeen_ConnectionJustAfterMidnightIsFiledInItsOwnDay(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 23, 59, 0, 0, time.UTC)
	env := newSeen(t, t.TempDir(), start, newFakeSeenUploader())
	env.p.PhoneOpen("early")
	env.p.PhoneClose("early")
	waitFor(t, "the first day on disk", func() bool { _, ok := readSeenFile(t, localSeen(env.dir, "20261013")); return ok })
	late := time.Date(2026, 10, 14, 0, 0, 10, 0, time.UTC)
	env.clock.set(late)
	env.p.PhoneOpen("late")
	env.p.PhoneClose("late")
	drainSeenWithin(env.p, 5*time.Second)
	ended := env.up.versions(seenKey("2026/10/13"))
	if len(ended) == 0 {
		t.Fatal("the ended day must be uploaded")
	}
	if _, ok := ended[len(ended)-1].Phones["late"]; ok {
		t.Fatalf("a connection after midnight must not be filed in the day before, got %+v", ended[len(ended)-1].Phones)
	}
	today := env.up.versions(seenKey("2026/10/14"))
	if len(today) == 0 || today[len(today)-1].Phones["late"] != (PhoneSeen{First: late, Last: late}) {
		t.Fatalf("a connection after midnight must be filed in its own day, got %+v", today)
	}
}

func TestPhonesSeen_UploadsWhatAnEarlierProcessLeftAndWarnsOncePerMinute(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	leftover := `{"schema":1,"node":"1111aaaa","day":"2026-10-12","phones":{"xyz":{"first":"2026-10-12T08:00:00Z","last":"2026-10-12T09:00:00Z"}}}`
	seed(t, dir, "20261012-1111aaaa.json", leftover)
	seed(t, dir, "20261012-1111aaaa.json.tmp", "{")
	seed(t, dir, "notes.txt", "kept")
	up := newFakeSeenUploader()
	up.setErr(errors.New("bucket down"))
	env := newSeen(t, dir, time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), up)
	failed := `msg="could not upload the lists of phones seen; they stay on disk and are tried again within a minute" files=1 err="bucket down"`
	waitFor(t, "the failed upload logged", func() bool { return strings.Contains(env.log.String(), failed) })
	waitFor(t, "more failed uploads held back", func() bool { return env.suppressed() >= 2 })
	if got := strings.Count(env.log.String(), failed); got != 1 {
		t.Fatalf("failed uploads must be warned about at most once a minute, got %d lines", got)
	}
	if _, ok := readSeenFile(t, filepath.Join(dir, "20261012-1111aaaa.json")); !ok {
		t.Fatal("a list that failed to upload must stay on disk")
	}
	up.setErr(nil)
	waitFor(t, "the leftover upload and removal", func() bool {
		_, ok := readSeenFile(t, filepath.Join(dir, "20261012-1111aaaa.json"))
		return !ok
	})
	got := up.versions(PhonesSeenPrefix + "2026/10/12/1111aaaa.json")
	if len(got) == 0 || got[0].Phones["xyz"].Last != time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) {
		t.Fatalf("the leftover must be uploaded under its own day and node, got %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "20261012-1111aaaa.json.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an unfinished list from an earlier run must be removed at start, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("files that are not lists of phones seen must be left alone: %v", err)
	}
	drainSeenWithin(env.p, 5*time.Second)
	if !strings.Contains(env.log.String(), `msg="more errors with the lists of phones seen happened and were not logged one by one"`) {
		t.Fatalf("the held-back warnings must be summed up at shutdown; log = %q", env.log.String())
	}
}

func linesWith(log, msg string) []string {
	var out []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, msg) {
			out = append(out, l)
		}
	}
	return out
}

func TestPhonesSeen_FailedSavesAreRetriedAndWarnedOncePerMinute(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC)
	fs := &seenFS{}
	fs.set(failAll(errors.New("disk full")), nil)
	env := newSeenWithFS(t, t.TempDir(), start, newFakeSeenUploader(), fs)
	env.p.PhoneOpen("abc")
	failed := `msg="could not save the list of phones seen today; it is tried again within a minute" day=2026-10-13`
	waitFor(t, "the failed save logged", func() bool { return len(linesWith(env.log.String(), failed)) == 1 })
	waitFor(t, "more failed saves held back", func() bool { return env.suppressed() >= 2 })
	if got := linesWith(env.log.String(), failed); len(got) != 1 || !strings.HasSuffix(got[0], `err="disk full" suppressed_since_last=0`) {
		t.Fatalf("failed saves must be warned about at most once a minute, got %q", got)
	}
	env.clock.set(start.Add(time.Minute))
	waitFor(t, "the next minute's warning", func() bool { return len(linesWith(env.log.String(), failed)) == 2 })
	if second := linesWith(env.log.String(), failed)[1]; strings.HasSuffix(second, "suppressed_since_last=0") {
		t.Fatalf("the next warning must count the held-back ones, got %q", second)
	}
	fs.set(nil, nil)
	waitFor(t, "the retried save", func() bool {
		f, ok := readSeenFile(t, localSeen(env.dir, "20261013"))
		return ok && f.Phones["abc"].First.Equal(start)
	})
}

func TestPhonesSeen_EndedDayThatFailsToSaveIsSavedAndUploadedLater(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 23, 58, 0, 0, time.UTC)
	fs := &seenFS{}
	env := newSeenWithFS(t, t.TempDir(), start, newFakeSeenUploader(), fs)
	env.p.PhoneOpen("abc")
	env.p.PhoneClose("abc")
	waitFor(t, "the first day on disk", func() bool { _, ok := readSeenFile(t, localSeen(env.dir, "20261013")); return ok })
	fs.set(failSuffix("20261013-"+testNode+".json", errors.New("disk full")), nil)
	env.clock.set(start.Add(time.Minute))
	env.p.PhoneOpen("unsaved")
	env.p.PhoneClose("unsaved")
	waitFor(t, "the failed save of the change", func() bool {
		return len(linesWith(env.log.String(), `msg="could not save the list of phones seen today; it is tried again within a minute" day=2026-10-13`)) >= 1
	})
	env.clock.set(time.Date(2026, 10, 14, 0, 1, 0, 0, time.UTC))
	waitFor(t, "the day rollover", func() bool {
		env.p.mu.Lock()
		defer env.p.mu.Unlock()
		return env.p.day.Equal(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	})
	env.clock.set(time.Date(2026, 10, 14, 0, 2, 30, 0, time.UTC))
	waitFor(t, "the ended day's failed save logged", func() bool {
		return len(linesWith(env.log.String(), `msg="could not save the list of phones seen on a day that has ended; it is tried again within a minute" day=2026-10-13`)) >= 1
	})
	fs.set(nil, nil)
	waitFor(t, "the ended day uploaded with the change", func() bool {
		v := env.up.versions(seenKey("2026/10/13"))
		if len(v) == 0 {
			return false
		}
		_, ok := v[len(v)-1].Phones["unsaved"]
		return ok
	})
}

func TestPhonesSeen_UploadedListThatCannotBeRemovedIsUploadedAgain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	leftover := filepath.Join(dir, "20261012-1111aaaa.json")
	seed(t, dir, "20261012-1111aaaa.json", `{"schema":1,"node":"1111aaaa","day":"2026-10-12","phones":{}}`)
	fs := &seenFS{}
	fs.set(nil, failSuffix("20261012-1111aaaa.json", errors.New("read-only")))
	env := newSeenWithFS(t, dir, time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader(), fs)
	waitFor(t, "the failed removal logged", func() bool {
		return strings.Contains(env.log.String(), `msg="could not remove an uploaded list of phones seen; it is uploaded again within a minute, replacing the same object" file=`+leftover+` err=read-only`)
	})
	waitFor(t, "the list uploaded again", func() bool { return len(env.up.versions(PhonesSeenPrefix+"2026/10/12/1111aaaa.json")) >= 2 })
	fs.set(nil, nil)
	waitFor(t, "the removal", func() bool { _, ok := readSeenFile(t, leftover); return !ok })
}

func TestPhonesSeen_RemovesAnUploadedListOnlyIfItWasNotReplaced(t *testing.T) {
	t.Parallel()
	env := newSeen(t, t.TempDir(), time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader())
	path := filepath.Join(env.dir, "20261011-2222bbbb.txt")
	if err := saveFileSynced(path, []byte("uploaded")); err != nil {
		t.Fatal(err)
	}
	uploaded, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveFileSynced(path, []byte("saved after the upload")); err != nil {
		t.Fatal(err)
	}
	if err := env.p.removeUploaded(path, uploaded); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "saved after the upload" {
		t.Fatalf("a list saved again after its upload must stay on disk for the next upload, got %q, %v", got, err)
	}
	same, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.p.removeUploaded(path, same); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the uploaded list itself must be removed, stat err = %v", err)
	}
	if err := env.p.removeUploaded(path, same); err != nil {
		t.Fatalf("a list already gone is no error, got %v", err)
	}
}

func TestPhonesSeen_UnfinishedListThatCannotBeRemovedIsLogged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tmp := seed(t, dir, "20261012-1111aaaa.json.tmp", "{")
	fs := &seenFS{}
	fs.set(nil, failSuffix(".json.tmp", errors.New("read-only")))
	env := newSeenWithFS(t, dir, time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader(), fs)
	if !strings.Contains(env.log.String(), `msg="could not remove an unfinished list of phones seen left from an earlier run; it stays on disk" file=`+tmp+` err=read-only`) {
		t.Fatalf("a temp file that cannot be removed must be logged; log = %q", env.log.String())
	}
}

func TestPhonesSeen_DrainUploadsTodayAndReleasesTheDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	start := time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC)
	env := newSeen(t, dir, start, newFakeSeenUploader())
	env.p.PhoneOpen("abc")
	waitFor(t, "the first upload", func() bool { return len(env.up.versions(seenKey("2026/10/13"))) == 1 })
	env.clock.set(start.Add(time.Minute))
	env.p.PhoneOpen("def")
	drainSeenWithin(env.p, 5*time.Second)
	got := env.up.versions(seenKey("2026/10/13"))
	if len(got) != 2 || len(got[1].Phones) != 2 {
		t.Fatalf("the drain must upload today's list even within the same quarter hour, got %+v", got)
	}
	again, err := NewPhonesSeen(context.Background(), dir, testNode, newFakeSeenUploader(), stderrLogger())
	if err != nil {
		t.Fatalf("the drain must release the directory, got %v", err)
	}
	drainSeenWithin(again, 5*time.Second)
}

func TestPhonesSeen_DrainLogsWhatIsLeftOnDisk(t *testing.T) {
	t.Parallel()
	up := newFakeSeenUploader()
	env := newSeen(t, t.TempDir(), time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), up)
	up.setErr(errors.New("bucket down"))
	env.p.PhoneOpen("abc")
	drainSeenWithin(env.p, 5*time.Second)
	if !strings.Contains(env.log.String(), `msg="could not upload the lists of phones seen before stopping; they stay on disk and are uploaded after the next start" files=1 err="bucket down"`) {
		t.Fatalf("a failed final upload must be logged; log = %q", env.log.String())
	}
	if _, ok := readSeenFile(t, localSeen(env.dir, "20261013")); !ok {
		t.Fatal("the list that failed to upload must stay on disk for the next start")
	}
}

func TestPhonesSeen_DrainIsBoundedByItsContext(t *testing.T) {
	t.Parallel()
	up := newFakeSeenUploader()
	up.block = true
	env := newSeen(t, t.TempDir(), time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), up)
	env.p.PhoneOpen("abc")
	select {
	case <-up.inFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("no upload started")
	}
	begin := time.Now()
	drainSeenWithin(env.p, 100*time.Millisecond)
	if took := time.Since(begin); took > 5*time.Second {
		t.Fatalf("the drain must end when its context does, even with an upload in flight; it took %s", took)
	}
	if _, ok := readSeenFile(t, localSeen(env.dir, "20261013")); !ok {
		t.Fatal("the list whose upload was cut short must stay on disk for the next start")
	}
	if !strings.Contains(env.log.String(), `msg="could not upload the lists of phones seen before stopping; they stay on disk and are uploaded after the next start" files=1 err="context canceled"`) {
		t.Fatalf("an upload cut short at shutdown must be logged; log = %q", env.log.String())
	}
}

func TestPhonesSeen_DrainSaysAFailedFinalSaveLosesItsChanges(t *testing.T) {
	t.Parallel()
	fs := &seenFS{}
	fs.set(failAll(errors.New("disk full")), nil)
	env := newSeenWithFS(t, t.TempDir(), time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader(), fs)
	env.p.PhoneOpen("abc")
	drainSeenWithin(env.p, 5*time.Second)
	if !strings.Contains(env.log.String(), `msg="could not save the list of phones seen today before stopping, so what changed since its last save is lost" day=2026-10-13 dir=`+env.dir+` err="disk full"`) {
		t.Fatalf("a failed final save must say what is lost; log = %q", env.log.String())
	}
}

func TestPhonesSeen_FailedSaveOfADayThatEndsMeanwhileIsKept(t *testing.T) {
	t.Parallel()
	fs := &seenFS{}
	env := newSeenWithFS(t, t.TempDir(), time.Date(2026, 10, 13, 23, 59, 0, 0, time.UTC), newFakeSeenUploader(), fs)
	var once sync.Once
	fs.set(func(path string) error {
		if !strings.HasSuffix(path, "20261013-"+testNode+".json") {
			return nil
		}
		fired := false
		once.Do(func() {
			env.clock.set(time.Date(2026, 10, 14, 0, 0, 5, 0, time.UTC))
			env.p.PhoneOpen("new")
			env.p.PhoneClose("new")
			fired = true
		})
		if fired {
			return errors.New("disk full")
		}
		return nil
	}, nil)
	env.p.PhoneOpen("old")
	env.p.PhoneClose("old")
	waitFor(t, "the ended day uploaded after its failed save", func() bool {
		v := env.up.versions(seenKey("2026/10/13"))
		if len(v) == 0 {
			return false
		}
		_, ok := v[len(v)-1].Phones["old"]
		return ok
	})
	waitFor(t, "the new day uploaded", func() bool {
		v := env.up.versions(seenKey("2026/10/14"))
		if len(v) == 0 {
			return false
		}
		_, ok := v[len(v)-1].Phones["new"]
		return ok
	})
}

func TestPhonesSeen_HeldDirectoryFailsFast(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	newSeen(t, dir, time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader())
	_, err := NewPhonesSeen(context.Background(), dir, testNode, newFakeSeenUploader(), stderrLogger())
	if err == nil || !strings.Contains(err.Error(), "store: phones-seen directory "+dir+" is in use by another process") {
		t.Fatalf("a second writer on the same directory must fail fast, got %v", err)
	}
}

func TestPhonesSeen_ConcurrentOpensAndClosesAreSafe(t *testing.T) {
	t.Parallel()
	env := newSeen(t, t.TempDir(), time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader())
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			name := fmt.Sprintf("p%02d", i%8)
			for range 50 {
				env.p.PhoneOpen(name)
				env.p.PhoneClose(name)
			}
		})
	}
	wg.Wait()
	drainSeenWithin(env.p, 5*time.Second)
	got := env.up.versions(seenKey("2026/10/13"))
	if len(got) == 0 || len(got[len(got)-1].Phones) != 8 {
		t.Fatalf("every phone must be on the final list, got %+v", got)
	}
}

func TestNewPhonesSeen_RejectsBadArguments(t *testing.T) {
	t.Parallel()
	logger := stderrLogger()
	fs := &seenFS{}
	tests := []struct {
		name   string
		dir    string
		node   string
		up     PhonesSeenUploader
		logger *slog.Logger
		opts   []phonesSeenOption
		want   string
	}{
		{name: "empty directory", node: testNode, up: newFakeSeenUploader(), logger: logger, want: "empty phones-seen directory"},
		{name: "node id not hex", dir: "x", node: "Node-1", up: newFakeSeenUploader(), logger: logger, want: `node id "Node-1" must be lowercase hex`},
		{name: "no uploader", dir: "x", node: testNode, logger: logger, want: "nil phones-seen uploader"},
		{name: "no logger", dir: "x", node: testNode, up: newFakeSeenUploader(), want: "nil phones-seen logger"},
		{name: "no clock", dir: "x", node: testNode, up: newFakeSeenUploader(), logger: logger, opts: []phonesSeenOption{withPhonesSeenClock(nil)}, want: "nil phones-seen clock"},
		{name: "zero tick", dir: "x", node: testNode, up: newFakeSeenUploader(), logger: logger, opts: []phonesSeenOption{withPhonesSeenTicks(0, time.Second)}, want: "non-positive phones-seen tick"},
		{name: "zero debounce", dir: "x", node: testNode, up: newFakeSeenUploader(), logger: logger, opts: []phonesSeenOption{withPhonesSeenTicks(time.Second, 0)}, want: "non-positive phones-seen tick"},
		{name: "no save", dir: "x", node: testNode, up: newFakeSeenUploader(), logger: logger, opts: []phonesSeenOption{withPhonesSeenFileOps(nil, fs.rm)}, want: "nil phones-seen file op"},
		{name: "no remove", dir: "x", node: testNode, up: newFakeSeenUploader(), logger: logger, opts: []phonesSeenOption{withPhonesSeenFileOps(fs.save, nil)}, want: "nil phones-seen file op"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewPhonesSeen(context.Background(), tc.dir, tc.node, tc.up, tc.logger, tc.opts...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewPhonesSeen error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}
