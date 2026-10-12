package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"

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
	switch {
	case opts.MasterName == "":
		return RedisConn{}, errors.New("master_name must not be empty")
	case opts.RouteByLatency || opts.RouteRandomly:
		return RedisConn{}, errors.New("route_by_latency / route_randomly need a cluster client, not the Sentinel failover client")
	case opts.ReplicaOnly:
		return RedisConn{}, errors.New("replica_only routes every command to read-only replicas; tunneld writes to the master")
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
	for _, src := range []string{raw, lenientUnescape(raw, false), lenientUnescape(raw, true)} {
		quoted := strconv.Quote(src)
		sources = append(sources, src, quoted[1:len(quoted)-1])
	}
	isDelim := func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune("\"'`:,()[]", r) }
	var b strings.Builder
	var tok strings.Builder
	flush := func() {
		if tok.Len() == 0 {
			return
		}
		t := tok.String()
		tok.Reset()
		for _, src := range sources {
			if strings.Contains(src, t) {
				b.WriteString("[redacted]")
				return
			}
		}
		b.WriteString(t)
	}
	for _, r := range msg {
		if isDelim(r) {
			flush()
			b.WriteRune(r)
			continue
		}
		tok.WriteRune(r)
	}
	flush()
	return b.String()
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
