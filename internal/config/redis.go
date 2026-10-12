package config

import (
	"errors"
	"fmt"
	"net/url"
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

func urlSecrets(raw string) []string {
	var secrets []string
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if at := strings.LastIndex(rest, "@"); at > 0 {
		secrets = append(secrets, rest[:at])
	}
	for s := raw; ; {
		i := strings.Index(s, "password=")
		if i < 0 {
			break
		}
		s = s[i+len("password="):]
		if s != "" {
			secrets = append(secrets, s)
		}
	}
	return secrets
}

func redactURLSecrets(msg, raw string) string {
	secrets := urlSecrets(raw)
	if len(secrets) == 0 {
		return msg
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
		if leaksSecret(t, secrets) {
			b.WriteString("[redacted]")
			return
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

func leaksSecret(token string, secrets []string) bool {
	for _, s := range secrets {
		if len(token) < 3 {
			for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
				if seg == token {
					return true
				}
			}
			continue
		}
		for i := 0; i+3 <= len(token); i++ {
			if strings.Contains(s, token[i:i+3]) {
				return true
			}
		}
	}
	return false
}
