package config_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/danielealbano/android-remote-control-mcp-tunneld/internal/config"
)

func envTwinsByFlag(t *testing.T) map[string][]string {
	t.Helper()
	var cli struct {
		Serve config.ServeCmd `cmd:""`
	}
	parser, err := kong.New(&cli, kong.Name("tunneld"), config.EnvTwins())
	if err != nil {
		t.Fatal(err)
	}
	envs := map[string][]string{}
	if err := kong.Visit(parser.Model, func(node kong.Visitable, next kong.Next) error {
		if flag, ok := node.(*kong.Flag); ok {
			envs[flag.Name] = flag.Envs
		}
		return next(nil)
	}); err != nil {
		t.Fatal(err)
	}
	return envs
}

func TestEnvTwins_Names(t *testing.T) {
	t.Parallel()
	envs := envTwinsByFlag(t)
	tests := []struct {
		name string
		flag string
		want string
	}{
		{name: "single word", flag: "listen", want: "TUNNELD_LISTEN"},
		{name: "multi word", flag: "limit-traffic-day", want: "TUNNELD_LIMIT_TRAFFIC_DAY"},
		{name: "digit in name", flag: "s3-endpoint", want: "TUNNELD_S3_ENDPOINT"},
		{name: "digit in multi-word name", flag: "s3-force-path-style", want: "TUNNELD_S3_FORCE_PATH_STYLE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := envs[tc.flag]
			if !ok {
				t.Fatalf("flag --%s not found", tc.flag)
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("--%s env twins = %v, want [%s]", tc.flag, got, tc.want)
			}
		})
	}
}

func TestEnvTwins_EveryFlagHasOnePlainTwin(t *testing.T) {
	t.Parallel()
	envs := envTwinsByFlag(t)
	valid := regexp.MustCompile(`^TUNNELD_[A-Z0-9]+(_[A-Z0-9]+)*$`)
	owner := map[string]string{}
	for flag, got := range envs {
		if flag == "help" {
			if len(got) != 0 {
				t.Errorf("--help env twins = %v, want none", got)
			}
			continue
		}
		want := "TUNNELD_" + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
		if len(got) != 1 || got[0] != want || !valid.MatchString(got[0]) {
			t.Errorf("--%s env twins = %v, want [%s]", flag, got, want)
			continue
		}
		if prev, dup := owner[got[0]]; dup {
			t.Errorf("env twin %s shared by --%s and --%s", got[0], prev, flag)
		}
		owner[got[0]] = flag
	}
	if len(owner) == 0 {
		t.Fatal("no flags visited")
	}
}
