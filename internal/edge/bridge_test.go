package edge

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/limit"
)

func TestEdge_OpenFar_LocalWhenOwner(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	te.local.has = true
	te.local.owns = true
	te.local.ds = &pipeStream{r: io.NopCloser(nil), w: io.Discard, closed: make(chan struct{})}

	far, closeFar, err := te.e.openFar(context.Background(), "t1", "node-a", "conn", "stream")
	if err != nil {
		t.Fatalf("openFar: %v", err)
	}
	defer closeFar()
	if far == nil {
		t.Fatal("far stream must be non-nil")
	}
	if te.local.opened != 1 || te.mesh.opened != 0 {
		t.Fatalf("owner==self must use the LOCAL dialer (local=%d mesh=%d)", te.local.opened, te.mesh.opened)
	}
}

func TestEdge_OpenFar_MeshWhenRemote(t *testing.T) {
	te := newTestEdge(t, baseConfig(), nil, nil)
	te.local.has = false // phone not local
	te.rtr.nodeAdv = "10.0.0.2:9443"
	te.rtr.nodeOK = true
	te.mesh.rwc = &pipeStream{r: io.NopCloser(nil), w: io.Discard, closed: make(chan struct{})}

	far, closeFar, err := te.e.openFar(context.Background(), "t1", "node-b", "conn", "stream")
	if err != nil {
		t.Fatalf("openFar: %v", err)
	}
	defer closeFar()
	if far == nil {
		t.Fatal("far stream must be non-nil")
	}
	if te.mesh.opened != 1 || te.local.opened != 0 {
		t.Fatalf("remote owner must use the MESH dialer (local=%d mesh=%d)", te.local.opened, te.mesh.opened)
	}
}

func TestEdge_PacedCopy_QuotaExhaustion(t *testing.T) {
	cfg := baseConfig()
	te := newTestEdge(t, cfg, nil, nil)
	// Swap in a limiter with a tiny day cap so ClaimTraffic refuses immediately.
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	te.e.lim = limit.NewLimiter(rdb, 1<<30, 4, 1<<40, time.Hour) // 4-byte day cap
	te.e.now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	src := &pipeStream{r: newBytesReader(make([]byte, 1024)), w: io.Discard, closed: make(chan struct{})}
	as := &activeStream{tunnel: "t1"}
	var counter int64
	got := te.e.pacedCopy(context.Background(), "t1", "in", io.Discard, src, as, &counter)
	if got != quotaHit {
		t.Fatalf("pacedCopy must stop with quotaHit on an exhausted day window, got %d", got)
	}
	if len(te.rec.quota) == 0 || te.rec.quota[0] != "day" {
		t.Fatalf("want a day QuotaExhausted record, got %v", te.rec.quota)
	}
}

func TestEdge_HandleTunnel_ReleasesStreamSlotOnce(t *testing.T) {
	name := "abcdef012345.example.test"
	cfg := baseConfig()
	cfg.Concurrent = 4
	te := newTestEdge(t, cfg, nil, nil)
	te.rtr.ok = true
	te.rtr.nodeID = "node-a"
	te.rtr.fp = "fp"
	te.rtr.connID = "conn"
	// openFar fails (no local, no mesh route) so handleTunnel takes the acquire→release path once.
	te.local.has = false
	te.rtr.nodeOK = false

	te.e.handleTunnel(context.Background(), newScriptConn("198.51.100.20", nil), ClientHelloInfo{SNI: name})

	// After a failed openFar, the acquired stream slot must be released (net zero), so a fresh acquire
	// up to the cap still succeeds --limit-concurrent times.
	acquired := 0
	for i := 0; i < cfg.Concurrent; i++ {
		ok, err := te.e.lim.AcquireStream(context.Background(), name, cfg.Concurrent)
		if err != nil {
			t.Fatalf("AcquireStream: %v", err)
		}
		if ok {
			acquired++
		}
	}
	if acquired != cfg.Concurrent {
		t.Fatalf("stream slot leaked: only %d/%d slots free after a failed bridge", acquired, cfg.Concurrent)
	}
}

// newBytesReader returns a reader over b that yields io.EOF after the bytes.
func newBytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b   []byte
	off int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}
