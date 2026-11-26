package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func metrics(counts map[string]int, countedAt time.Time) string {
	var b strings.Builder
	b.WriteString("# HELP arc_active_users Phones (one per tunnel name) with a control connection in the last window, from tunneld's lists of phones seen.\n")
	b.WriteString("# TYPE arc_active_users gauge\n")
	for _, w := range windows {
		fmt.Fprintf(&b, "arc_active_users{window=%q} %d\n", w.label, counts[w.label])
	}
	b.WriteString("# HELP arc_active_users_counted_timestamp_seconds Time of the count in arc_active_users.\n")
	b.WriteString("# TYPE arc_active_users_counted_timestamp_seconds gauge\n")
	fmt.Fprintf(&b, "arc_active_users_counted_timestamp_seconds %d\n", countedAt.Unix())
	return b.String()
}

type fileWriter func(path string, data []byte, mode os.FileMode) error

func writeTextfile(write fileWriter, path string, counts map[string]int, countedAt time.Time) error {
	return write(path, []byte(metrics(counts, countedAt)), 0o644)
}
