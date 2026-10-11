package acme

import (
	"context"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

const (
	httpChallengePrefix = "/.well-known/acme-challenge/"
	maxChallengeToken   = 256
	maxChallengeHost    = 253
)

type HTTPKeyAuths interface {
	HTTPKeyAuth(ctx context.Context, domain, token string) (string, bool, error)
}

func HTTPChallengeHandler(keyAuths HTTPKeyAuths, onMiss func(clientIP string), logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientHost(r.RemoteAddr)
		token, isChallenge := strings.CutPrefix(r.URL.Path, httpChallengePrefix)
		host := challengeHost(r.Host)
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !isChallenge || !validChallengeToken(token) || host == "" {
			onMiss(ip)
			http.NotFound(w, r)
			return
		}
		keyAuth, found, err := keyAuths.HTTPKeyAuth(r.Context(), host, token)
		if err != nil {
			logger.Debug("acme http-01 challenge lookup failed", "domain", host, "ip", ip, "err", err)
			http.Error(w, "challenge store unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			onMiss(ip)
			http.NotFound(w, r)
			return
		}
		logger.Debug("acme http-01 challenge served", "domain", host, "ip", ip)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, html.EscapeString(keyAuth))
	})
}

func clientHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func challengeHost(hostHeader string) string {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > maxChallengeHost {
		return ""
	}
	return host
}

func validChallengeToken(token string) bool {
	if token == "" || len(token) > maxChallengeToken {
		return false
	}
	for _, c := range []byte(token) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
