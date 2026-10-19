package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseRedisURL_Variants(t *testing.T) {
	t.Parallel()
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
			t.Parallel()
			c, err := ParseRedisURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseRedisURL(%q) error = %v, wantErr %v", tc.url, err, tc.wantErr)
			}
			if err == nil && (c.failover != nil) != tc.wantSentinel {
				t.Fatalf("sentinel = %v, want %v", c.failover != nil, tc.wantSentinel)
			}
		})
	}
}

func TestParseRedisURL_SentinelCredentials(t *testing.T) {
	t.Parallel()
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

func TestParseRedisURL_PoolOptionsReachTheClient(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		url  string
	}{
		{name: "sentinel", url: "redis://s1.example.test:26379?master_name=tunneld&pool_size=200&conn_max_idle_time=5m"},
		{name: "single node", url: "redis://valkey.example.test:6379?pool_size=200&conn_max_idle_time=5m"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := ParseRedisURL(tc.url)
			if err != nil {
				t.Fatal(err)
			}
			rdb := c.NewClient()
			t.Cleanup(func() {
				if err := rdb.Close(); err != nil {
					t.Errorf("close client: %v", err)
				}
			})
			o := rdb.Options()
			if o.PoolSize != 200 || o.ConnMaxIdleTime != 5*time.Minute {
				t.Fatalf("pool_size = %d, conn_max_idle_time = %s, want 200 / 5m", o.PoolSize, o.ConnMaxIdleTime)
			}
		})
	}
}

func TestParseRedisURL_PlainKeepsOptions(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestParseRedisURL_ErrorRedactsCredentials(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		url   string
		frags []string
	}{
		{name: "control character", url: "redis://user:Secr3tPa-ssw0rd@valkey.example.test:6379/0\x7f", frags: []string{"Secr3tPa", "ssw0rd"}},
		{name: "slash in userinfo password", url: "redis://user:Secr3tPa/ssw0rd@valkey.example.test:6379/0", frags: []string{"Secr3tPa", "ssw0rd"}},
		{name: "question mark in userinfo password", url: "redis://user:Secr3tPa?ssw0rd@valkey.example.test:6379/0", frags: []string{"Secr3tPa", "ssw0rd"}},
		{name: "hash in userinfo password", url: "redis://user:Secr3tPa#ssw0rd@valkey.example.test:6379/0", frags: []string{"Secr3tPa", "ssw0rd"}},
		{name: "bad escape in userinfo password", url: "redis://user:Secr3tPa%zzssw0rd@valkey.example.test:6379/0", frags: []string{"Secr3tPa", "%zz"}},
		{name: "short symbolic password head", url: "redis://:a+/Zm9vYmFyYmF6cXV4@valkey.example.test:6379/0", frags: []string{"a+", "Zm9v"}},
		{name: "bang password head", url: "redis://u:a!/Zm9vYmFyYmF6cXV4@valkey.example.test:6379/0", frags: []string{"a!"}},
		{name: "leading bang password head", url: "redis://u:!x/Zm9vYmFyYmF6cXV4@valkey.example.test:6379/0", frags: []string{"!x"}},
		{name: "punctuation password head", url: "redis://u:.-?Zm9vYmFyYmF6cXV4@valkey.example.test:6379/0", frags: []string{".-"}},
		{name: "plus password head", url: "redis://default:+/Zm9vYmFyYmF6cXV4@valkey.example.test:6379/0", frags: []string{"+"}},
		{name: "ampersand in master password", url: "redis://s1.example.test:26379?master_name=tunneld&password=Secr3tPa&ssw0rd", frags: []string{"ssw0rd"}},
		{name: "percent-encoded password key", url: "redis://s1.example.test:26379?master_name=t&%70assword=x&Zm9vYmFyYmF6cXV4", frags: []string{"Zm9v"}},
		{name: "percent-encoded password key with bad escape", url: "redis://valkey.example.test:6379/0?pass%77ord=Secr3tPa%zzssw0rd", frags: []string{"%zz", "Secr3tPa"}},
		{name: "bad escape in master password", url: "redis://valkey.example.test:6379/0?password=Secr3tPa%zzssw0rd", frags: []string{"%zz", "Secr3tPa"}},
		{name: "single-slash scheme", url: "redis:/user:pw@valkey.example.test", frags: []string{"pw"}},
		{name: "quote in single-slash password", url: `redis:/user:a"bc@valkey.example.test`, frags: []string{`a\`, "bc"}},
		{name: "sentinel bad addr", url: "redis://user:Secr3tPa-ssw0rd@s1.example.test:26379?master_name=tunneld&addr=no-port", frags: []string{"Secr3tPa"}},
		{name: "plain bad db", url: "redis://user:Secr3tPa-ssw0rd@valkey.example.test:6379/not-a-db", frags: []string{"Secr3tPa"}},
		{name: "invalid UTF-8 after an escape in master password", url: "redis://valkey.example.test:6379/0?password=Xy7&%A3kLmN0pQr", frags: []string{"kLmN0pQr", "Xy7"}},
		{name: "invalid UTF-8 in sentinel master password", url: "redis://s1.example.test:26379?master_name=tunneld&password=Xy7&%E2%82kLmN0pQr", frags: []string{"kLmN0pQr"}},
		{name: "split multi-byte escape in query", url: "redis://valkey.example.test:6379/0?password=Secr3t%€x", frags: []string{"Secr3t", `\xe2`}},
		{name: "split multi-byte escape in userinfo", url: "redis://user:/%€xSecret@valkey.example.test:6379/0", frags: []string{"Secret", `\xe2`}},
		{name: "missing scheme keeps credentials", url: "Admin:Secr3t@valkey.example.test:6379", frags: []string{"admin", "Admin", "Secr3t"}},
		{name: "delimiter-only master password fragment", url: "redis://s1.example.test:26379?master_name=m&password=Xy&:[]()", frags: []string{"Xy", ":[]()"}},
		{name: "delimiters in a password parsed as the db path", url: "redis://u:12/(),'@valkey.example.test:6379", frags: []string{"(),'"}},
		{name: "delimiters inside a master password fragment", url: "redis://valkey.example.test:6379/0?password=ab&cd:ef(gh", frags: []string{"cd", "ef", "gh", ":", "("}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseRedisURL(tc.url)
			if err == nil {
				t.Fatalf("ParseRedisURL(%q) must fail", tc.url)
			}
			msg := err.Error()
			cause, ok := strings.CutPrefix(msg, "--redis-url: ")
			if !ok || cause == "" {
				t.Fatalf("the redacted cause must still be emitted with its context, got %q", msg)
			}
			for _, frag := range tc.frags {
				if strings.Contains(cause, frag) {
					t.Fatalf("a --redis-url error must not carry any part of the password (%q), got %q", frag, msg)
				}
			}
			kept := strings.ReplaceAll(cause, "[redacted]", "\x00")
			for i := 0; i < len(kept); i++ {
				if c := kept[i]; strings.IndexByte(" \t\n\r\"'`:,()[]", c) >= 0 && strings.IndexByte(tc.url, c) >= 0 {
					t.Fatalf("no delimiter taken from the URL may survive, %q did in %q", c, msg)
				}
			}
			for _, tok := range strings.FieldsFunc(kept, func(r rune) bool { return r == 0 || strings.ContainsRune(" \t\n\"'`:,()[]", r) }) {
				if strings.Contains(tc.url, tok) {
					t.Fatalf("every token taken from the URL must be redacted, %q survived in %q", tok, msg)
				}
			}
		})
	}
}

func TestRedactURLSecrets_KeepsErrorStructure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		msg  string
		url  string
		want string
	}{
		{name: "URL-derived run with its punctuation", msg: `invalid port ":a+" after host`, url: "redis://:a+/x@valkey.example.test:6379/0", want: `invalid port "[redacted]" after host`},
		{name: "percent-encoded key's value", msg: `unexpected option: Zm9v`, url: "redis://s1.example.test:26379?master_name=t&%70assword=x&Zm9v", want: `unexpected option[redacted] [redacted]`},
		{name: "delimiters around URL tokens merge into one marker", msg: `invalid database number: "(),'@valkey.example.test:6379"`, url: "redis://u:12/(),'@valkey.example.test:6379", want: `invalid database number[redacted] "[redacted]"`},
		{name: "delimiter-only fragment", msg: `unexpected option: :[]()`, url: "redis://s1.example.test:26379?master_name=m&password=Xy&:[]()", want: `unexpected option[redacted] [redacted]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := redactURLSecrets(tc.msg, tc.url); got != tc.want {
				t.Fatalf("redactURLSecrets(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestParseRedisURL_OwnErrorsAreVerbatim(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "empty master", url: "redis://s1.example.test:26379?master_name=", want: "--redis-url: master_name must not be empty"},
		{name: "route randomly", url: "redis://s1.example.test:26379?master_name=tunneld&route_randomly=true", want: "--redis-url: route_by_latency / route_randomly need a cluster client, not the Sentinel failover client"},
		{name: "route by latency", url: "redis://s1.example.test:26379?master_name=tunneld&route_by_latency=true", want: "--redis-url: route_by_latency / route_randomly need a cluster client, not the Sentinel failover client"},
		{name: "replica only", url: "redis://s1.example.test:26379?master_name=tunneld&replica_only=true", want: "--redis-url: replica_only routes every command to read-only replicas; tunneld writes to the master"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseRedisURL(tc.url); err == nil || err.Error() != tc.want {
				t.Fatalf("ParseRedisURL(%q) error = %v, want %q", tc.url, err, tc.want)
			}
		})
	}
}
