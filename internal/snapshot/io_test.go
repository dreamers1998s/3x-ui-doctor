package snapshot

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/3x-ui-doctor/3x-ui-doctor/internal/model"
)

func TestWriteDoesNotOverwriteWithoutForce(t *testing.T) {
	originalRestrictor := restrictOutputPermissions
	restrictOutputPermissions = func(string) error { return nil }
	defer func() { restrictOutputPermissions = originalRestrictor }()
	path := filepath.Join(t.TempDir(), "baseline.json")
	value := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion}
	if err := WriteJSON(path, value, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, value, false); err == nil {
		t.Fatal("overwrote output without force")
	}
	if err := WriteJSON(path, value, true); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(path)
	if err != nil || loaded.SchemaVersion != 1 {
		t.Fatalf("read failed: %v %+v", err, loaded)
	}
	if info, err := os.Stat(path); runtime.GOOS != "windows" && err == nil && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("output permissions too broad: %v", info.Mode().Perm())
	}
}

func TestReadRejectsWrongSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("unsupported schema accepted")
	}
}
