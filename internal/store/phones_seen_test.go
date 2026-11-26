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
	mu   sync.Mutex
	puts map[string][]PhonesSeenFile
	err  error
}

func newFakeSeenUploader() *fakeSeenUploader {
	return &fakeSeenUploader{puts: map[string][]PhonesSeenFile{}}
}

func (f *fakeSeenUploader) PutPhonesSeenFile(_ context.Context, key string, body io.ReadSeeker, size int64) error {
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

type seenEnv struct {
	p     *PhonesSeen
	dir   string
	clock *fakeClock
	up    *fakeSeenUploader
	log   *syncBuf
}

func newSeen(t *testing.T, dir string, at time.Time, up *fakeSeenUploader) seenEnv {
	t.Helper()
	clock := newClock(at)
	log := &syncBuf{}
	p, err := NewPhonesSeen(context.Background(), dir, testNode, up, slog.New(slog.NewTextHandler(log, nil)),
		withPhonesSeenClock(clock.now), withPhonesSeenTicks(2*time.Millisecond, time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { drainSeenWithin(p, 5*time.Second) })
	return seenEnv{p: p, dir: dir, clock: clock, up: up, log: log}
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

func TestPhonesSeen_SavesEachPhoneAndUploadsOncePerQuarterHour(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC)
	env := newSeen(t, t.TempDir(), start, newFakeSeenUploader())
	local := filepath.Join(env.dir, "20261013-"+testNode+".json")
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
	local := filepath.Join(env.dir, "20261013-"+testNode+".json")
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
	waitFor(t, "the ended day's upload and removal", func() bool {
		_, ok := readSeenFile(t, filepath.Join(env.dir, "20261013-"+testNode+".json"))
		return !ok && len(env.up.versions(seenKey("2026/10/14"))) == 1
	})
	ended := env.up.versions(seenKey("2026/10/13"))
	last := ended[len(ended)-1]
	if got := last.Phones["abc"].Last; !got.Equal(time.Date(2026, 10, 13, 23, 59, 59, 999999999, time.UTC)) {
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

func TestPhonesSeen_UploadsWhatAnEarlierProcessLeft(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	leftover := `{"schema":1,"node":"1111aaaa","day":"2026-10-12","phones":{"xyz":{"first":"2026-10-12T08:00:00Z","last":"2026-10-12T09:00:00Z"}}}`
	seed(t, dir, "20261012-1111aaaa.json", leftover)
	seed(t, dir, "20261012-1111aaaa.json.tmp", "{")
	seed(t, dir, "notes.txt", "kept")
	up := newFakeSeenUploader()
	up.setErr(errors.New("bucket down"))
	env := newSeen(t, dir, time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), up)
	waitFor(t, "the failed upload logged", func() bool {
		return strings.Contains(env.log.String(), `msg="could not upload the lists of phones seen; they stay on disk and are tried again within a minute" files=1 err="bucket down"`)
	})
	if _, ok := readSeenFile(t, filepath.Join(dir, "20261012-1111aaaa.json")); !ok {
		t.Fatal("a list that failed to upload must stay on disk")
	}
	up.setErr(nil)
	waitFor(t, "the leftover upload and removal", func() bool {
		_, ok := readSeenFile(t, filepath.Join(dir, "20261012-1111aaaa.json"))
		return !ok
	})
	got := up.versions(PhonesSeenPrefix + "2026/10/12/1111aaaa.json")
	if len(got) != 1 || got[0].Phones["xyz"].Last != time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) {
		t.Fatalf("the leftover must be uploaded under its own day and node, got %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "20261012-1111aaaa.json.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an unfinished list from an earlier run must be removed at start, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatalf("files that are not lists of phones seen must be left alone: %v", err)
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
	_, err := NewPhonesSeen(context.Background(), dir, testNode, newFakeSeenUploader(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("the drain must release the directory, got %v", err)
	}
}

func TestPhonesSeen_DrainLogsWhatIsLeftOnDisk(t *testing.T) {
	t.Parallel()
	up := newFakeSeenUploader()
	env := newSeen(t, t.TempDir(), time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), up)
	up.setErr(errors.New("bucket down"))
	env.p.PhoneOpen("abc")
	drainSeenWithin(env.p, 5*time.Second)
	if !strings.Contains(env.log.String(), `msg="could not save or upload every list of phones seen before stopping; what is on disk is uploaded after the next start"`) {
		t.Fatalf("a failed final upload must be logged; log = %q", env.log.String())
	}
	if _, ok := readSeenFile(t, filepath.Join(env.dir, "20261013-"+testNode+".json")); !ok {
		t.Fatal("the list that failed to upload must stay on disk for the next start")
	}
}

func TestPhonesSeen_HeldDirectoryFailsFast(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	newSeen(t, dir, time.Date(2026, 10, 13, 10, 2, 0, 0, time.UTC), newFakeSeenUploader())
	_, err := NewPhonesSeen(context.Background(), dir, testNode, newFakeSeenUploader(), slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
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
