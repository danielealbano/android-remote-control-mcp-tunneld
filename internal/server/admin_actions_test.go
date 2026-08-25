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

// newTestRegistry builds a router.Registry backed by an in-process miniredis.
func newTestRegistry(t *testing.T) *router.Registry {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return router.NewRegistry(rdb, 30*time.Second)
}

// recordingLocal is a local controller-method stub for the owner-local admin path: it records the tunnel it
// was called with (empty until called) and returns the configured result.
func recordingLocal(result bool) (fn func(context.Context, string) (bool, error), calledName *string) {
	var name string
	return func(_ context.Context, tunnel string) (bool, error) {
		name = tunnel
		return result, nil
	}, &name
}

// actionReq builds a POST to the per-tunnel action path with the {name} path value injected (as the
// ServeMux would), unless name is empty (to exercise the missing-name guard).
func actionReq(action, name string) *http.Request {
	r := httptest.NewRequest("POST", "http://internal/api/v1/admin/tunnels/"+name+"/"+action, nil)
	if name != "" {
		r.SetPathValue("name", name)
	}
	return r
}

func TestAdminAction_NonPost(t *testing.T) {
	local, _ := recordingLocal(true)
	h := adminActionHandler("nodeA", newTestRegistry(t), nil, testLogger(), "renew", "reissued", local)
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://internal/api/v1/admin/tunnels/t/reissue", nil)
	req.SetPathValue("name", "t")
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET must be 405, got %d", w.Code)
	}
}

func TestAdminAction_MissingName(t *testing.T) {
	local, _ := recordingLocal(true)
	h := adminActionHandler("nodeA", newTestRegistry(t), nil, testLogger(), "renew", "reissued", local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("reissue", "")) // no path value set → empty name
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing name must be 400, got %d", w.Code)
	}
}

func TestAdminReissue_NoRoute(t *testing.T) {
	local, calledName := recordingLocal(true)
	h := adminActionHandler("nodeA", newTestRegistry(t), nil, testLogger(), "renew", "reissued", local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("reissue", "nobody"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("an unbound tunnel must be 404, got %d", w.Code)
	}
	if *calledName != "" {
		t.Error("the local method must not be called when no route is bound")
	}
}

func TestAdminReissue_Local(t *testing.T) {
	reg := newTestRegistry(t)
	if err := reg.BindRoute(context.Background(), "t", "nodeA", "fp", "conn1"); err != nil {
		t.Fatalf("bind route: %v", err)
	}
	local, calledName := recordingLocal(true)
	h := adminActionHandler("nodeA", reg, nil, testLogger(), "renew", "reissued", local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("reissue", "t"))
	if w.Code != http.StatusOK {
		t.Fatalf("local reissue must be 200, got %d", w.Code)
	}
	if *calledName != "t" {
		t.Errorf("local called with %q, want t", *calledName)
	}
	var resp struct {
		Tunnel   string `json:"tunnel"`
		Owner    string `json:"owner"`
		Reissued bool   `json:"reissued"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Tunnel != "t" || resp.Owner != "nodeA" || !resp.Reissued {
		t.Errorf("response = %+v, want {tunnel:t owner:nodeA reissued:true}", resp)
	}
}

func TestAdminTerminate_Local(t *testing.T) {
	reg := newTestRegistry(t)
	if err := reg.BindRoute(context.Background(), "t", "nodeA", "fp", "conn1"); err != nil {
		t.Fatalf("bind route: %v", err)
	}
	local, calledName := recordingLocal(true)
	h := adminActionHandler("nodeA", reg, nil, testLogger(), "terminate", "terminated", local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("terminate", "t"))
	if w.Code != http.StatusOK {
		t.Fatalf("local terminate must be 200, got %d", w.Code)
	}
	if *calledName != "t" {
		t.Errorf("local called with %q, want t", *calledName)
	}
	var resp struct {
		Tunnel     string `json:"tunnel"`
		Owner      string `json:"owner"`
		Terminated bool   `json:"terminated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Tunnel != "t" || resp.Owner != "nodeA" || !resp.Terminated {
		t.Errorf("response = %+v, want {tunnel:t owner:nodeA terminated:true}", resp)
	}
}
