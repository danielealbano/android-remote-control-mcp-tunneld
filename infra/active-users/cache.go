package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const cacheSchema = 1

type cache struct {
	Schema int                   `json:"schema"`
	Lists  map[string]cachedList `json:"lists"`
}

type cachedList struct {
	ETag string               `json:"etag"`
	Last map[string]time.Time `json:"last"`
}

func (j *job) loadCache() cache {
	empty := cache{Schema: cacheSchema, Lists: map[string]cachedList{}}
	body, err := os.ReadFile(j.CacheFile)
	if errors.Is(err, os.ErrNotExist) {
		j.Logger.Info("this node has no cache yet, so every list of phones seen is read from the bucket", "cache_file", j.CacheFile)
		return empty
	}
	if err != nil {
		j.Logger.Warn("could not read this node's cache, so every list of phones seen is read from the bucket again", "cache_file", j.CacheFile, "err", err)
		return empty
	}
	var c cache
	if err := json.Unmarshal(body, &c); err != nil {
		j.Logger.Warn("could not decode this node's cache, so every list of phones seen is read from the bucket again", "cache_file", j.CacheFile, "err", err)
		return empty
	}
	if c.Schema != cacheSchema || c.Lists == nil {
		j.Logger.Warn("this node's cache has another format, so every list of phones seen is read from the bucket again", "cache_file", j.CacheFile, "schema", c.Schema)
		return empty
	}
	return c
}

func (j *job) saveCache(c cache) error {
	body, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode the cache: %w", err)
	}
	return j.write(j.CacheFile, body, 0o600)
}
