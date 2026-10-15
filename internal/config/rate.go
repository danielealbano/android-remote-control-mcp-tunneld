package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Rate struct {
	Count  int
	Period time.Duration
	Burst  int
}

func ParseRate(s string) (Rate, error) {
	spec, burst, hasBurst := strings.Cut(strings.TrimSpace(s), ":")
	count, period, ok := strings.Cut(spec, "/")
	if !ok {
		return Rate{}, fmt.Errorf("rate %q must be <count>/<period>[:<burst>]", s)
	}
	n, err := strconv.Atoi(count)
	if err != nil || n < 1 {
		return Rate{}, fmt.Errorf("rate %q: count must be a positive integer", s)
	}
	d, err := time.ParseDuration(period)
	if err != nil || d <= 0 {
		return Rate{}, fmt.Errorf("rate %q: period must be a positive duration", s)
	}
	r := Rate{Count: n, Period: d, Burst: n}
	if hasBurst {
		b, err := strconv.Atoi(burst)
		if err != nil || b < 1 {
			return Rate{}, fmt.Errorf("rate %q: burst must be a positive integer", s)
		}
		r.Burst = b
	}
	return r, nil
}
