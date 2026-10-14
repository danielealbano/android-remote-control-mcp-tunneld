package server

import (
	"context"
	"errors"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/phoneconn"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/wire"
)

// fakePhoneControl records SendRenewNudge / Close calls (with a shared monotonic order counter) for the
// adminController tests; it satisfies phoneControl.
type fakePhoneControl struct {
	order       *int
	nudgeName   string
	nudgeResult bool
	nudgeOrder  int
	closeName   string
	closeReason string
	closeResult bool
	closeOrder  int
	openName    string
	openConnID  string
	openPayload wire.OpenPayload
	openErr     error
}

func (f *fakePhoneControl) SendOpen(_ context.Context, name, connID string, open wire.OpenPayload) error {
	f.openName, f.openConnID, f.openPayload = name, connID, open
	return f.openErr
}

func (f *fakePhoneControl) SendRenewNudge(name, _, _ string) bool {
	*f.order++
	f.nudgeOrder = *f.order
	f.nudgeName = name
	return f.nudgeResult
}

func (f *fakePhoneControl) Close(name, reason string) bool {
	*f.order++
	f.closeOrder = *f.order
	f.closeName = name
	f.closeReason = reason
	return f.closeResult
}

// TestAdminController_Renew: Renew mints a nonce and calls SendRenewNudge(name, …, ""), returning its bool;
// a nonce-mint error propagates and never nudges.
func TestAdminController_Renew(t *testing.T) {
	order := 0
	ph := &fakePhoneControl{order: &order, nudgeResult: true}
	c := &adminController{
		mgr:          ph,
		nonce:        func(context.Context) (string, error) { return "abcd", nil },
		evictStreams: func(string) {},
	}
	ok, err := c.Renew(context.Background(), "t")
	if err != nil || !ok {
		t.Fatalf("Renew = (%v, %v), want (true, nil)", ok, err)
	}
	if ph.nudgeName != "t" {
		t.Errorf("SendRenewNudge name = %q, want t", ph.nudgeName)
	}

	// A nonce-mint error propagates and never nudges.
	order = 0
	ph2 := &fakePhoneControl{order: &order}
	c2 := &adminController{
		mgr:          ph2,
		nonce:        func(context.Context) (string, error) { return "", errors.New("boom") },
		evictStreams: func(string) {},
	}
	if ok, err := c2.Renew(context.Background(), "t"); ok || err == nil {
		t.Fatalf("a nonce error must return (false, err), got (%v, %v)", ok, err)
	}
	if ph2.nudgeOrder != 0 {
		t.Error("SendRenewNudge must not be called when the nonce mint fails")
	}
}

// TestAdminController_Terminate_EvictThenClose: Terminate evicts this node's splices BEFORE closing the
// phone conn, closes with reason admin-terminate, and returns Close's bool.
func TestAdminController_Terminate_EvictThenClose(t *testing.T) {
	order := 0
	var evictName string
	var evictOrder int
	ph := &fakePhoneControl{order: &order, closeResult: true}
	c := &adminController{
		mgr:   ph,
		nonce: func(context.Context) (string, error) { return "", nil },
		evictStreams: func(name string) {
			order++
			evictOrder = order
			evictName = name
		},
		evictConn: func(string, string, string) bool { return false },
	}
	ok, err := c.Terminate(context.Background(), "t")
	if err != nil || !ok {
		t.Fatalf("Terminate = (%v, %v), want (true, nil)", ok, err)
	}
	if evictName != "t" || ph.closeName != "t" {
		t.Errorf("evictName=%q closeName=%q, want both t", evictName, ph.closeName)
	}
	if ph.closeReason != store.CloseAdminTerminate {
		t.Errorf("close reason = %q, want %q", ph.closeReason, store.CloseAdminTerminate)
	}
	if evictOrder >= ph.closeOrder {
		t.Errorf("evict must precede close: evictOrder=%d closeOrder=%d", evictOrder, ph.closeOrder)
	}
}

func TestAdminController_Open(t *testing.T) {
	errOther := errors.New("encode failed")
	open := wire.OpenPayload{Token: "TOKEN", Addr: "203.0.113.10:443", UseHTTPS: true}
	tests := []struct {
		name        string
		sendErr     error
		wantApplied bool
		wantErr     error
	}{
		{name: "no live connection", sendErr: phoneconn.ErrNoConn},
		{name: "queued", wantApplied: true},
		{name: "other error", sendErr: errOther, wantErr: errOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ph := &fakePhoneControl{order: new(int), openErr: tc.sendErr}
			c := &adminController{mgr: ph}
			applied, err := c.Open(context.Background(), "t", "conn-1", open)
			if applied != tc.wantApplied || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("Open = (%v, %v), want (%v, %v)", applied, err, tc.wantApplied, tc.wantErr)
			}
			if ph.openName != "t" || ph.openConnID != "conn-1" || ph.openPayload != open {
				t.Fatalf("SendOpen got (%q, %q, %+v)", ph.openName, ph.openConnID, ph.openPayload)
			}
		})
	}
}

func TestAdminController_Evict(t *testing.T) {
	var got [3]string
	c := &adminController{evictConn: func(name, connID, reason string) bool {
		got = [3]string{name, connID, reason}
		return true
	}}
	applied, err := c.Evict(context.Background(), "t", "conn-1", store.CloseBanEvict)
	if err != nil || !applied {
		t.Fatalf("Evict = (%v, %v), want (true, nil)", applied, err)
	}
	if got != [3]string{"t", "conn-1", store.CloseBanEvict} {
		t.Fatalf("evictConn got %v", got)
	}
}
