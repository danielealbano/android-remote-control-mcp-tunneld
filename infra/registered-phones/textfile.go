package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func metrics(registered int) string {
	return fmt.Sprintf("# HELP arc_registered_phones Phones enrolled since the first counted day that got a certificate, renewed or not.\n"+
		"# TYPE arc_registered_phones gauge\narc_registered_phones %d\n", registered)
}

func writeTextfile(path string, registered int) (err error) {
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
	if _, err := tmp.WriteString(metrics(registered)); err != nil {
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

func removeTextfile(path string, cause error) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, fmt.Errorf("remove the dashboard file %s: %w", path, err))
	}
	return cause
}
