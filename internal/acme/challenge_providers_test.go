package acme

import (
	"context"
	"errors"
	"testing"
)

type fakeChallenges struct {
	calls []string
	err   error
}

func (f *fakeChallenges) PutTLSALPN(_ context.Context, domain, keyAuth string) error {
	f.calls = append(f.calls, "put-alpn "+domain+" "+keyAuth)
	return f.err
}

func (f *fakeChallenges) DeleteTLSALPN(_ context.Context, domain, keyAuth string) error {
	f.calls = append(f.calls, "del-alpn "+domain+" "+keyAuth)
	return f.err
}

func (f *fakeChallenges) PutHTTP(_ context.Context, domain, token, keyAuth string) error {
	f.calls = append(f.calls, "put-http "+domain+" "+token+" "+keyAuth)
	return f.err
}

func (f *fakeChallenges) DeleteHTTP(_ context.Context, domain, token, keyAuth string) error {
	f.calls = append(f.calls, "del-http "+domain+" "+token+" "+keyAuth)
	return f.err
}

func TestTLSALPNProvider_PresentCleanUp(t *testing.T) {
	t.Parallel()
	f := &fakeChallenges{}
	p := &tlsALPNProvider{s: f}
	ctx := context.Background()
	if err := p.Present(ctx, "a.example.test", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanUp(ctx, "a.example.test", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	want := []string{"put-alpn a.example.test ka", "del-alpn a.example.test ka"}
	if len(f.calls) != 2 || f.calls[0] != want[0] || f.calls[1] != want[1] {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	f.err = ErrChallengePending
	if err := p.Present(ctx, "a.example.test", "tok", "ka"); !errors.Is(err, ErrChallengePending) {
		t.Fatalf("Present error = %v, want the store error", err)
	}
	if err := p.CleanUp(ctx, "a.example.test", "tok", "ka"); !errors.Is(err, ErrChallengePending) {
		t.Fatalf("CleanUp error = %v, want the store error", err)
	}
}

func TestHTTPProvider_PresentCleanUp(t *testing.T) {
	t.Parallel()
	f := &fakeChallenges{}
	p := &httpProvider{s: f}
	ctx := context.Background()
	if err := p.Present(ctx, "a.example.test", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanUp(ctx, "a.example.test", "tok", "ka"); err != nil {
		t.Fatal(err)
	}
	want := []string{"put-http a.example.test tok ka", "del-http a.example.test tok ka"}
	if len(f.calls) != 2 || f.calls[0] != want[0] || f.calls[1] != want[1] {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	f.err = ErrChallengeStore
	if err := p.Present(ctx, "a.example.test", "tok", "ka"); !errors.Is(err, ErrChallengeStore) {
		t.Fatalf("Present error = %v, want the store error", err)
	}
	if err := p.CleanUp(ctx, "a.example.test", "tok", "ka"); !errors.Is(err, ErrChallengeStore) {
		t.Fatalf("CleanUp error = %v, want the store error", err)
	}
}
