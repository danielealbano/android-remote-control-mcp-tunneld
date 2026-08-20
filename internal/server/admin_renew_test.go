package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
)

// stubController is a mesh.Controller for the /admin/renew local-nudge path (no phoneconn needed).
type stubController struct {
	called bool
	tunnel string
	nudged bool
	err    error
}

func (s *stubController) Renew(_ context.Context, tunnel string) (bool, error) {
	s.called = true
	s.tunnel = tunnel
	return s.nudged, s.err
}

// newTestRegistry builds a router.Registry backed by an in-process miniredis.
func newTestRegistry(t *testing.T) *router.Registry {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return router.NewRegistry(rdb, 30*time.Second)
}

func TestAdminRenew_NonPost(t *testing.T) {
	h := adminRenewHandler("nodeA", newTestRegistry(t), &stubController{}, nil, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "http://internal/admin/renew?tunnel=t", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /admin/renew must be 405, got %d", w.Code)
	}
}

func TestAdminRenew_MissingTunnel(t *testing.T) {
	h := adminRenewHandler("nodeA", newTestRegistry(t), &stubController{}, nil, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://internal/admin/renew", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing tunnel must be 400, got %d", w.Code)
	}
}

func TestAdminRenew_NoRoute(t *testing.T) {
	ctl := &stubController{nudged: true}
	h := adminRenewHandler("nodeA", newTestRegistry(t), ctl, nil, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://internal/admin/renew?tunnel=nobody", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("an unbound tunnel must be 404, got %d", w.Code)
	}
	if ctl.called {
		t.Error("the controller must not be called when no route is bound")
	}
}

func TestAdminRenew_Local(t *testing.T) {
	reg := newTestRegistry(t)
	// Bind the route to THIS node so the handler takes the local nudge path.
	if err := reg.BindRoute(context.Background(), "t", "nodeA", "fp", "conn1"); err != nil {
		t.Fatalf("bind route: %v", err)
	}
	ctl := &stubController{nudged: true}
	h := adminRenewHandler("nodeA", reg, ctl, nil, testLogger())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "http://internal/admin/renew?tunnel=t", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("local renew must be 200, got %d", w.Code)
	}
	if !ctl.called || ctl.tunnel != "t" {
		t.Errorf("controller called=%v tunnel=%q, want called=true tunnel=t", ctl.called, ctl.tunnel)
	}
	var resp struct {
		Tunnel string `json:"tunnel"`
		Owner  string `json:"owner"`
		Nudged bool   `json:"nudged"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Tunnel != "t" || resp.Owner != "nodeA" || !resp.Nudged {
		t.Errorf("response = %+v, want {tunnel:t owner:nodeA nudged:true}", resp)
	}
}
