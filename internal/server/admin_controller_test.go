package server

import (
	"context"
	"errors"
	"testing"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/store"
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
