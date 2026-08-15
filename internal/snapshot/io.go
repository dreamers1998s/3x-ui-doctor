package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

const maxSnapshotBytes = 128 << 20

var restrictOutputPermissions = restrictPermissions

func Read(path string) (model.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("open baseline: %w", err)
	}
	defer f.Close()
	limited := io.LimitReader(f, maxSnapshotBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return model.Snapshot{}, errors.New("read baseline failed")
	}
	if len(body) > maxSnapshotBytes {
		return model.Snapshot{}, errors.New("baseline exceeds size limit")
	}
	var value model.Snapshot
	if err := json.Unmarshal(body, &value); err != nil {
		return model.Snapshot{}, errors.New("baseline is not valid JSON")
	}
	if value.SchemaVersion != model.SnapshotSchemaVersion {
		return model.Snapshot{}, fmt.Errorf("unsupported baseline schema_version %d", value.SchemaVersion)
	}
	return value, nil
}

func WriteJSON(path string, value any, force bool) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	body = append(body, '\n')
	return Write(path, body, force)
}

func Write(path string, body []byte, force bool) error {
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(body)
		return err
	}
	info, inspectErr := os.Lstat(path)
	if inspectErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to write through a symbolic link")
		}
		if !force {
			return errors.New("output already exists; use --force to replace it")
		}
	} else if !os.IsNotExist(inspectErr) {
		return fmt.Errorf("inspect output: %w", inspectErr)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".xui-doctor-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("initialize output permissions: %w", err)
	}
	if _, err = temp.Write(body); err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close output: %w", closeErr)
	}
	if err := restrictOutputPermissions(tempPath); err != nil {
		return fmt.Errorf("restrict output permissions: %w", err)
	}
	reserved := false
	if inspectErr != nil {
		reservation, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("reserve output path: %w", err)
		}
		_ = reservation.Close()
		reserved = true
	}
	if err := os.Rename(tempPath, path); err != nil {
		if reserved {
			_ = os.Remove(path)
		}
		return fmt.Errorf("atomically replace output: %w", err)
	}
	cleanup = false
	return nil
}
