package config

import (
	"strings"

	"github.com/alecthomas/kong"
)

const envTwinPrefix = "TUNNELD_"

func EnvTwins() kong.Option {
	return kong.PostBuild(func(k *kong.Kong) error {
		return kong.Visit(k.Model, func(node kong.Visitable, next kong.Next) error {
			if flag, ok := node.(*kong.Flag); ok && flag.Name != "help" {
				env := envTwinPrefix + strings.ToUpper(strings.ReplaceAll(flag.Name, "-", "_"))
				flag.Envs = []string{env}
				flag.Tag.Envs = []string{env}
			}
			return next(nil)
		})
	})
}
