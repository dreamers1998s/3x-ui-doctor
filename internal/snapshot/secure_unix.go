//go:build !windows

package snapshot

import (
	"fmt"
	"os"
)

func restrictPermissions(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("output remains accessible to group or others")
	}
	return nil
}
