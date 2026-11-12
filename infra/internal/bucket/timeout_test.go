package bucket

import (
	"testing"
	"time"
)

func TestConfig_RequestTimeout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{name: "no timeout set keeps the default", set: 0, want: DefaultTimeout},
		{name: "a negative timeout keeps the default", set: -time.Second, want: DefaultTimeout},
		{name: "a set timeout is used", set: 2 * time.Minute, want: 2 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := (Config{Timeout: tc.set}).requestTimeout(); got != tc.want {
				t.Fatalf("requestTimeout() = %s, want %s", got, tc.want)
			}
		})
	}
}
