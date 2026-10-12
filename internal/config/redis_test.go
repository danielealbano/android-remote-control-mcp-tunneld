package config

import (
	"slices"
	"testing"
)

func TestParseRedisURL_Variants(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		wantErr      bool
		wantSentinel bool
	}{
		{name: "plain", url: "redis://:pw@valkey.example.test:6379/0"},
		{name: "sentinel", url: "redis://s1.example.test:26379?master_name=tunneld&addr=s2.example.test:26379", wantSentinel: true},
		{name: "malformed plain path", url: "redis://valkey.example.test:6379/not-a-db", wantErr: true},
		{name: "not a url", url: "://not-a-url", wantErr: true},
		{name: "malformed query", url: "redis://valkey.example.test:6379/0?a=%zz", wantErr: true},
		{name: "sentinel bad addr", url: "redis://s1.example.test:26379?master_name=tunneld&addr=no-port", wantErr: true},
		{name: "sentinel unknown option", url: "redis://s1.example.test:26379?master_name=tunneld&bogus=1", wantErr: true},
		{name: "sentinel empty master", url: "redis://s1.example.test:26379?master_name=", wantErr: true},
		{name: "sentinel route randomly", url: "redis://s1.example.test:26379?master_name=tunneld&route_randomly=true", wantErr: true},
		{name: "sentinel route by latency", url: "redis://s1.example.test:26379?master_name=tunneld&route_by_latency=true", wantErr: true},
		{name: "sentinel replica only", url: "redis://s1.example.test:26379?master_name=tunneld&replica_only=true", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseRedisURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseRedisURL(%q) error = %v, wantErr %v", tc.url, err, tc.wantErr)
			}
			if err == nil && c.Sentinel() != tc.wantSentinel {
				t.Fatalf("Sentinel() = %v, want %v", c.Sentinel(), tc.wantSentinel)
			}
		})
	}
}

func TestParseRedisURL_SentinelCredentials(t *testing.T) {
	c, err := ParseRedisURL("redis://sentuser:sentpw@s1.example.test:26379/2?master_name=tunneld&addr=s2.example.test:26379&username=masteruser&password=masterpw")
	if err != nil {
		t.Fatal(err)
	}
	f := c.failover
	if f.MasterName != "tunneld" || f.DB != 2 {
		t.Fatalf("master = %q db = %d, want tunneld / 2", f.MasterName, f.DB)
	}
	if want := []string{"s1.example.test:26379", "s2.example.test:26379"}; !slices.Equal(f.SentinelAddrs, want) {
		t.Fatalf("sentinels = %v, want %v", f.SentinelAddrs, want)
	}
	if f.SentinelUsername != "sentuser" || f.SentinelPassword != "sentpw" {
		t.Fatalf("the URL userinfo must authenticate to the sentinels, got %q/%q", f.SentinelUsername, f.SentinelPassword)
	}
	if f.Username != "masteruser" || f.Password != "masterpw" {
		t.Fatalf("username= / password= must authenticate to the master, got %q/%q", f.Username, f.Password)
	}
}

func TestParseRedisURL_PlainKeepsOptions(t *testing.T) {
	c, err := ParseRedisURL("redis://user:pw@valkey.example.test:6380/3")
	if err != nil {
		t.Fatal(err)
	}
	o := c.single
	if o.Addr != "valkey.example.test:6380" || o.Username != "user" || o.Password != "pw" || o.DB != 3 {
		t.Fatalf("plain options = %+v", o)
	}
}

func TestValidate_RedisURLSentinel(t *testing.T) {
	c := validCfg(t)
	c.RedisURL = "redis://s1.example.test:26379?master_name=tunneld&addr=s2.example.test:26379&password=pw"
	if err := c.Validate(); err != nil {
		t.Fatalf("a Sentinel --redis-url must validate: %v", err)
	}
	c.RedisURL = "redis://s1.example.test:26379?master_name=tunneld&addr=no-port"
	if err := c.Validate(); err == nil {
		t.Fatal("a malformed Sentinel --redis-url must be rejected")
	}
}
