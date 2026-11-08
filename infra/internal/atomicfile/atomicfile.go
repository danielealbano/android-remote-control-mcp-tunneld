package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var ErrNotFlushed = errors.New("the file was replaced but its directory could not be flushed to disk")

func Write(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s to flush the file to disk: %w", dir, err)
	}
	replaced := false
	defer func() {
		cerr := d.Close()
		switch {
		case cerr == nil:
		case replaced:
			err = errors.Join(err, fmt.Errorf("%w: close %s: %w", ErrNotFlushed, dir, cerr))
		default:
			err = errors.Join(err, fmt.Errorf("close %s: %w", dir, cerr))
		}
	}()
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temporary file next to %s: %w", path, err)
	}
	defer func() {
		if err != nil && !replaced {
			if rerr := os.Remove(tmp.Name()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove %s: %w", tmp.Name(), rerr))
			}
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", tmp.Name(), err), tmp.Close())
	}
	if err := tmp.Chmod(mode); err != nil {
		return errors.Join(fmt.Errorf("set the mode of %s: %w", tmp.Name(), err), tmp.Close())
	}
	if err := tmp.Sync(); err != nil {
		return errors.Join(fmt.Errorf("flush %s to disk: %w", tmp.Name(), err), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	replaced = true
	if err := d.Sync(); err != nil {
		return fmt.Errorf("%w: flush %s to disk: %w", ErrNotFlushed, dir, err)
	}
	return nil
}
