package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

type RedisConn struct {
	single   *redis.Options
	failover *redis.FailoverOptions
}

func ParseRedisURL(redisURL string) (RedisConn, error) {
	c, err := parseRedisURL(redisURL)
	if err != nil {
		return RedisConn{}, fmt.Errorf("--redis-url: %s", redactURLSecrets(err.Error(), redisURL))
	}
	if f := c.failover; f != nil {
		switch {
		case f.MasterName == "":
			return RedisConn{}, errors.New("--redis-url: master_name must not be empty")
		case f.RouteByLatency || f.RouteRandomly:
			return RedisConn{}, errors.New("--redis-url: route_by_latency / route_randomly need a cluster client, not the Sentinel failover client")
		case f.ReplicaOnly:
			return RedisConn{}, errors.New("--redis-url: replica_only routes every command to read-only replicas; tunneld writes to the master")
		}
	}
	return c, nil
}

func parseRedisURL(redisURL string) (RedisConn, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return RedisConn{}, ue.Err
		}
		return RedisConn{}, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return RedisConn{}, fmt.Errorf("query: %w", err)
	}
	if !q.Has("master_name") {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			return RedisConn{}, err
		}
		return RedisConn{single: opts}, nil
	}
	opts, err := redis.ParseFailoverURL(redisURL)
	if err != nil {
		return RedisConn{}, err
	}
	return RedisConn{failover: opts}, nil
}

func (c RedisConn) NewClient() *redis.Client {
	if c.failover != nil {
		return redis.NewFailoverClient(c.failover)
	}
	return redis.NewClient(c.single)
}

func redactURLSecrets(msg, raw string) string {
	var sources []string
	var inURL [256]bool
	srcs := []string{raw, lenientUnescape(raw, false)}
	if q := strings.IndexByte(raw, '?'); q >= 0 {
		srcs = append(srcs, lenientUnescape(raw[q:], true))
	}
	for _, src := range srcs {
		quoted := strconv.Quote(src)
		for _, form := range []string{src, quoted[1 : len(quoted)-1]} {
			form = strings.ToLower(form)
			sources = append(sources, form)
			for i := 0; i < len(form); i++ {
				inURL[form[i]] = true
			}
		}
	}
	var b strings.Builder
	hidden := false
	emit := func(part string, secret bool) {
		if !secret {
			b.WriteString(part)
		} else if !hidden {
			b.WriteString("[redacted]")
		}
		hidden = secret
	}
	start := 0
	for i := 0; i < len(msg); i++ {
		if strings.IndexByte(" \t\n\r\"'`:,()[]", msg[i]) >= 0 {
			if i > start {
				emit(msg[start:i], fromURL(msg[start:i], sources))
			}
			emit(msg[i:i+1], inURL[msg[i]])
			start = i + 1
		}
	}
	if start < len(msg) {
		emit(msg[start:], fromURL(msg[start:], sources))
	}
	return b.String()
}

func fromURL(tok string, sources []string) bool {
	for i := 0; i < len(tok); i++ {
		if tok[i] >= 0x80 || tok[i] == '\\' {
			return true
		}
	}
	lower := strings.ToLower(tok)
	for _, src := range sources {
		if strings.Contains(src, lower) {
			return true
		}
	}
	return false
}

func lenientUnescape(s string, plusAsSpace bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case s[i] == '+' && plusAsSpace:
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
