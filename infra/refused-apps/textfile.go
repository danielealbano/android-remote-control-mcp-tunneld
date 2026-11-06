package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type rowKey struct {
	app     string
	key     string
	version int64
	ip      string
}

type row struct {
	rowKey
	count     int
	firstSeen int64
	lastSeen  int64
}

func rows(list attemptList) []row {
	byKey := make(map[rowKey]*row)
	for app, attempts := range list.Apps {
		for _, a := range attempts {
			k := rowKey{app: app, key: a.Key, version: a.Version, ip: a.IP}
			at := a.At.Unix()
			r, ok := byKey[k]
			if !ok {
				r = &row{rowKey: k, firstSeen: at, lastSeen: at}
				byKey[k] = r
			}
			r.count++
			r.firstSeen = min(r.firstSeen, at)
			r.lastSeen = max(r.lastSeen, at)
		}
	}
	out := make([]row, 0, len(byKey))
	for _, r := range byKey {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.app != b.app:
			return a.app < b.app
		case a.key != b.key:
			return a.key < b.key
		case a.version != b.version:
			return a.version < b.version
		default:
			return a.ip < b.ip
		}
	})
	return out
}

func metrics(list attemptList) string {
	rs := rows(list)
	var b strings.Builder
	families := []struct {
		name, help string
		value      func(row) int64
	}{
		{"arc_refused_app_attempts", "Refused enrollment attempts per app, signing key, app version and source address.", func(r row) int64 { return int64(r.count) }},
		{"arc_refused_app_first_seen_timestamp_seconds", "Time of the first refused enrollment attempt per app, signing key, app version and source address.", func(r row) int64 { return r.firstSeen }},
		{"arc_refused_app_last_seen_timestamp_seconds", "Time of the last refused enrollment attempt per app, signing key, app version and source address.", func(r row) int64 { return r.lastSeen }},
	}
	for _, f := range families {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", f.name, f.help, f.name)
		for _, r := range rs {
			fmt.Fprintf(&b, "%s{app=\"%s\",key=\"%s\",version=\"%d\",ip=\"%s\"} %d\n",
				f.name, labelValue(r.app), labelValue(r.key), r.version, labelValue(r.ip), f.value(r))
		}
	}
	return b.String()
}

func labelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(strings.ToValidUTF8(s, "\uFFFD"))
}

func writeTextfile(path string, list attemptList) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temporary file next to %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			if rerr := os.Remove(tmp.Name()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove %s: %w", tmp.Name(), rerr))
			}
		}
	}()
	if _, err := tmp.WriteString(metrics(list)); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", tmp.Name(), err), tmp.Close())
	}
	if err := tmp.Chmod(0o644); err != nil {
		return errors.Join(fmt.Errorf("set the mode of %s: %w", tmp.Name(), err), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
