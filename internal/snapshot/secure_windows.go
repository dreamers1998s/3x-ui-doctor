//go:build windows

package snapshot

import (
	"fmt"
	"os/exec"
	"os/user"
)

func restrictPermissions(path string) error {
	current, err := user.Current()
	if err != nil || current.Uid == "" {
		return fmt.Errorf("current Windows user SID is unavailable")
	}
	// Remove inherited ACEs and grant only the current SID full control. The
	// leading * tells icacls that the identity is a SID, avoiding localization
	// and renamed-account ambiguity.
	identity := "*" + current.Uid + ":(F)"
	cmd := exec.Command("icacls.exe", path, "/inheritance:r", "/grant:r", identity)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("icacls failed: %w", err)
	}
	return nil
}
