package acme

import "context"

type TLSALPNChallenges interface {
	PutTLSALPN(ctx context.Context, domain, keyAuth string) error
	DeleteTLSALPN(ctx context.Context, domain, keyAuth string) error
}

type HTTPChallenges interface {
	PutHTTP(ctx context.Context, domain, token, keyAuth string) error
	DeleteHTTP(ctx context.Context, domain, token, keyAuth string) error
}

type tlsALPNProvider struct{ s TLSALPNChallenges }

func (p *tlsALPNProvider) Present(ctx context.Context, domain, _, keyAuth string) error {
	if err := p.s.PutTLSALPN(ctx, domain, keyAuth); err != nil {
		return err
	}
	if tr := trackFrom(ctx); tr != nil {
		tr.onAbandon(func(cctx context.Context) error { return p.s.DeleteTLSALPN(cctx, domain, keyAuth) })
	}
	return nil
}

func (p *tlsALPNProvider) CleanUp(ctx context.Context, domain, _, keyAuth string) error {
	return p.s.DeleteTLSALPN(ctx, domain, keyAuth)
}

type httpProvider struct{ s HTTPChallenges }

func (p *httpProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	return p.s.PutHTTP(ctx, domain, token, keyAuth)
}

func (p *httpProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	return p.s.DeleteHTTP(ctx, domain, token, keyAuth)
}
