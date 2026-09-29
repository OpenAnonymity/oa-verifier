package certstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileStoreRoundtrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "certs")
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := fs.Load(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: got %v, want ErrNotFound", err)
	}

	want := testBundle(t, "verifier.example", 90*24*time.Hour)
	if err := fs.Save(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, want)

	if _, _, err := got.TLSCertificate(); err != nil {
		t.Fatalf("loaded bundle is not a usable key pair: %v", err)
	}

	// Permissions: file 0600, directory 0700.
	fi, err := os.Stat(fs.path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bundle file mode = %o, want 0600", perm)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir mode = %o, want 0700", perm)
	}

	// Overwrite replaces content and leaves no temp files behind.
	second := testBundle(t, "verifier.example", 60*24*time.Hour)
	if err := fs.Save(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, err = fs.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBundleEqual(t, got, second)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one file, got %d", len(entries))
	}
}

func TestFileStoreAtomicOnFailedWrite(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	ctx := context.Background()
	want := testBundle(t, "verifier.example", 90*24*time.Hour)
	if err := fs.Save(ctx, want); err != nil {
		t.Fatal(err)
	}

	// Make the rename fail by turning the target path into a directory that
	// is not empty: rename(2) refuses to replace a non-empty directory.
	if err := os.Remove(fs.path()); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fs.path(), "occupied"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fs.Save(ctx, want); err == nil {
		t.Fatal("expected save to fail when rename is impossible")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind after failed save: %s", e.Name())
		}
	}
}

func TestFileStoreRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	if err := os.WriteFile(fs.path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Load(context.Background()); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt file: got %v, want decode error", err)
	}
	// An empty file counts as not found rather than an error.
	if err := os.WriteFile(fs.path(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty file: got %v, want ErrNotFound", err)
	}
}

func TestNewFileStoreRequiresDir(t *testing.T) {
	if _, err := NewFileStore(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}
