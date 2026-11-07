package main

import (
	"fmt"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/atomicfile"
)

func metrics(registered int, countedAt time.Time) string {
	return fmt.Sprintf("# HELP arc_registered_phones Phones enrolled since the first counted day that got a certificate, renewed or not.\n"+
		"# TYPE arc_registered_phones gauge\narc_registered_phones %d\n"+
		"# HELP arc_registered_phones_counted_timestamp_seconds Time of the count in arc_registered_phones.\n"+
		"# TYPE arc_registered_phones_counted_timestamp_seconds gauge\narc_registered_phones_counted_timestamp_seconds %d\n",
		registered, countedAt.Unix())
}

func writeTextfile(path string, registered int, countedAt time.Time) error {
	return atomicfile.Write(path, []byte(metrics(registered, countedAt)), 0o644)
}
