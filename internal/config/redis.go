package config

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/redis/go-redis/v9"
)

type RedisConn struct {
	single   *redis.Options
	failover *redis.FailoverOptions
}

func ParseRedisURL(redisURL string) (RedisConn, error) {
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

func (c RedisConn) Sentinel() bool { return c.failover != nil }

func (c RedisConn) NewClient() *redis.Client {
	if c.failover != nil {
		return redis.NewFailoverClient(c.failover)
	}
	return redis.NewClient(c.single)
}
