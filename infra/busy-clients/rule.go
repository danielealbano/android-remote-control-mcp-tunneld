package main

import (
	"fmt"
	"net/netip"
	"time"
)

type usage struct {
	address      string
	lookup       netip.Addr
	connections  int
	tunnels      map[string]struct{}
	fingerprints map[string]struct{}
	first, last  time.Time
}

type rule struct {
	connections       int
	spreadConnections int
	spreadTunnels     int
}

func (r rule) validate() error {
	if r.connections <= 0 || r.spreadConnections <= 0 || r.spreadTunnels <= 0 {
		return fmt.Errorf("the rule's numbers must be positive: connections %d, spread connections %d, spread tunnels %d",
			r.connections, r.spreadConnections, r.spreadTunnels)
	}
	return nil
}

func (r rule) flags(u *usage) bool {
	return u.connections >= r.connections || u.connections >= r.spreadConnections && len(u.tunnels) >= r.spreadTunnels
}

func (r rule) describe() string {
	return fmt.Sprintf("%d or more connections, or %d or more to at least %d tunnels", r.connections, r.spreadConnections, r.spreadTunnels)
}
