package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Write(path string, data []byte, mode os.FileMode) (err error) {
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
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", tmp.Name(), err), tmp.Close())
	}
	if err := tmp.Chmod(mode); err != nil {
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
