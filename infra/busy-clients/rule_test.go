package main

import (
	"fmt"
	"testing"
)

func usageWith(connections, tunnels int) *usage {
	u := &usage{connections: connections, tunnels: map[string]struct{}{}}
	for i := range tunnels {
		u.tunnels[fmt.Sprintf("t%d", i)] = struct{}{}
	}
	return u
}

func TestRule_Flags(t *testing.T) {
	t.Parallel()
	r := rule{connections: 500, spreadConnections: 100, spreadTunnels: 3}
	tests := []struct {
		name                 string
		connections, tunnels int
		want                 bool
	}{
		{name: "500 connections to one tunnel", connections: 500, tunnels: 1, want: true},
		{name: "499 connections to two tunnels", connections: 499, tunnels: 2},
		{name: "100 connections to three tunnels", connections: 100, tunnels: 3, want: true},
		{name: "99 connections to five tunnels", connections: 99, tunnels: 5},
		{name: "150 connections to two tunnels", connections: 150, tunnels: 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := r.flags(usageWith(tc.connections, tc.tunnels)); got != tc.want {
				t.Fatalf("flags = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRule_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		r       rule
		wantErr bool
	}{
		{name: "positive numbers", r: rule{connections: 500, spreadConnections: 100, spreadTunnels: 3}},
		{name: "zero connections", r: rule{connections: 0, spreadConnections: 100, spreadTunnels: 3}, wantErr: true},
		{name: "negative spread connections", r: rule{connections: 500, spreadConnections: -1, spreadTunnels: 3}, wantErr: true},
		{name: "zero spread tunnels", r: rule{connections: 500, spreadConnections: 100, spreadTunnels: 0}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.r.validate(); (err != nil) != tc.wantErr {
				t.Fatalf("validate() = %v, want an error: %v", err, tc.wantErr)
			}
		})
	}
}
