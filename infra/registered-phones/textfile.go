package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/danielealbano/android-remote-control-mcp-tunneld/infra/internal/textfile"
)

var errTextfileKept = errors.New("the old dashboard file could not be removed")

func metrics(registered int, countedAt time.Time) string {
	return fmt.Sprintf("# HELP arc_registered_phones Phones enrolled since the first counted day that got a certificate, renewed or not.\n"+
		"# TYPE arc_registered_phones gauge\narc_registered_phones %d\n"+
		"# HELP arc_registered_phones_counted_timestamp_seconds Time of the count in arc_registered_phones.\n"+
		"# TYPE arc_registered_phones_counted_timestamp_seconds gauge\narc_registered_phones_counted_timestamp_seconds %d\n",
		registered, countedAt.Unix())
}

func writeTextfile(path string, registered int, countedAt time.Time) error {
	return textfile.Write(path, metrics(registered, countedAt))
}

func removeTextfile(path string, cause error) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, fmt.Errorf("%w: %w", errTextfileKept, err))
	}
	return cause
}
