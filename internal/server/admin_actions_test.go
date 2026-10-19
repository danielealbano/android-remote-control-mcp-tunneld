package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/router"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/tunneltest"
)

// newTestRegistry builds a router.Registry backed by an in-process miniredis.
func newTestRegistry(t *testing.T) *router.Registry {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { tunneltest.CloseOrLog(t, rdb) })
	reg, err := router.NewRegistry(rdb, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return reg
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
	if err := reg.BindRoute(context.Background(), "t", "nodeA", "conn1"); err != nil {
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
	if err := reg.BindRoute(context.Background(), "t", "nodeA", "conn1"); err != nil {
		t.Fatalf("bind route: %v", err)
	}
	registerNodes(t, reg, "nodeA")
	local, calledName := recordingLocal(true)
	h := adminTerminateHandler("nodeA", reg, &fakeMeshControl{}, testLogger(), local)
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

func registerNodes(t *testing.T, reg *router.Registry, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := reg.RegisterNode(context.Background(), id, router.NodeInfo{Advertise: id + ":9443"}, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
}

type terminateResp struct {
	Tunnel     string `json:"tunnel"`
	Owner      string `json:"owner"`
	Terminated bool   `json:"terminated"`
}

func TestAdminTerminate_BroadcastsToEveryNode(t *testing.T) {
	reg := newTestRegistry(t)
	if err := reg.BindRoute(context.Background(), "t", "nodeB", "conn1"); err != nil {
		t.Fatal(err)
	}
	registerNodes(t, reg, "nodeA", "nodeB", "nodeC")
	mc := &fakeMeshControl{applied: map[string]bool{"nodeB:9443": true}}
	local, calledName := recordingLocal(false)
	h := adminTerminateHandler("nodeA", reg, mc, testLogger(), local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("terminate", "t"))
	if w.Code != http.StatusOK {
		t.Fatalf("terminate = %d, want 200", w.Code)
	}
	if *calledName != "t" {
		t.Fatal("the local terminate must run")
	}
	peers := map[string]int{}
	for _, c := range mc.snapshot() {
		if c.req.Op != "terminate" || c.req.Tunnel != "t" {
			t.Fatalf("broadcast request = %+v", c.req)
		}
		peers[c.peer]++
	}
	if len(peers) != 2 || peers["nodeB:9443"] != 1 || peers["nodeC:9443"] != 1 {
		t.Fatalf("terminate sent to %v, want every other node once", peers)
	}
	var resp terminateResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp != (terminateResp{Tunnel: "t", Owner: "nodeB", Terminated: true}) {
		t.Fatalf("response = %+v", resp)
	}
}

func TestAdminTerminate_NoRouteIs404(t *testing.T) {
	reg := newTestRegistry(t)
	registerNodes(t, reg, "nodeA", "nodeB")
	mc := &fakeMeshControl{}
	local, calledName := recordingLocal(true)
	h := adminTerminateHandler("nodeA", reg, mc, testLogger(), local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("terminate", "nobody"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("terminate = %d, want 404", w.Code)
	}
	if *calledName != "" || len(mc.snapshot()) != 0 {
		t.Fatal("no node may be called when no route is bound")
	}
}

func TestAdminTerminate_OwnerUnavailableIs502(t *testing.T) {
	reg := newTestRegistry(t)
	if err := reg.BindRoute(context.Background(), "t", "nodeGone", "conn1"); err != nil {
		t.Fatal(err)
	}
	registerNodes(t, reg, "nodeA", "nodeB")
	mc := &fakeMeshControl{}
	local, calledName := recordingLocal(false)
	h := adminTerminateHandler("nodeA", reg, mc, testLogger(), local)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, actionReq("terminate", "t"))
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "owner node unavailable") {
		t.Fatalf("terminate = %d %q, want 502 owner node unavailable", w.Code, w.Body.String())
	}
	if *calledName != "t" || len(mc.snapshot()) != 1 {
		t.Fatal("every live node must still be called")
	}
}

func TestAdminTerminate_FailureStatuses(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		localErr error
		meshErrs map[string]error
		wantCode int
	}{
		{name: "owner mesh call fails", owner: "nodeB", meshErrs: map[string]error{"nodeB:9443": errors.New("peer down")}, wantCode: http.StatusBadGateway},
		{name: "local owner terminate fails", owner: "nodeA", localErr: errors.New("boom"), wantCode: http.StatusBadGateway},
		{name: "non-owner fails", owner: "nodeB", meshErrs: map[string]error{"nodeC:9443": errors.New("peer down")}, wantCode: http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := newTestRegistry(t)
			if err := reg.BindRoute(context.Background(), "t", tc.owner, "conn1"); err != nil {
				t.Fatal(err)
			}
			registerNodes(t, reg, "nodeA", "nodeB", "nodeC")
			mc := &fakeMeshControl{errs: tc.meshErrs}
			localCalled := false
			local := func(context.Context, string) (bool, error) { localCalled = true; return false, tc.localErr }
			buf := &syncBuffer{}
			h := adminTerminateHandler("nodeA", reg, mc, slog.New(slog.NewTextHandler(buf, nil)), local)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, actionReq("terminate", "t"))
			if w.Code != tc.wantCode {
				t.Fatalf("terminate = %d, want %d", w.Code, tc.wantCode)
			}
			if !localCalled || len(mc.snapshot()) != 2 {
				t.Fatalf("every node must still be called: local=%v mesh=%d", localCalled, len(mc.snapshot()))
			}
			if tc.wantCode == http.StatusOK {
				var resp terminateResp
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Tunnel != "t" {
					t.Fatalf("a non-owner failure must still return the JSON result: %q (%v)", w.Body.String(), err)
				}
				if !strings.Contains(buf.String(), "node=nodeC") {
					t.Fatalf("the non-owner failure must be logged; log = %q", buf.String())
				}
			}
		})
	}
}
