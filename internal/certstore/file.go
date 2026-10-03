package certstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileStore keeps the bundle in a single file under Dir. Files are created
// 0600 and the directory 0700; writes go to a temporary file in the same
// directory which is fsynced and then renamed over the target, so a crash
// mid-write leaves either the old or the new bundle, never a torn one.
//
// Plaintext use is only appropriate for storage that stays inside the enclave
// (an emptyDir / tmpfs mount, local development). For anything that survives
// the enclave (Azure Files, Key Vault) wrap it in a SealedStore.
type FileStore struct {
	Dir string
	// FileName inside Dir; the TLS bundle name when empty.
	FileName string
}

const bundleFileName = "tls-bundle.json"

// NewFileStore returns a FileStore rooted at dir holding the TLS bundle.
func NewFileStore(dir string) (*FileStore, error) {
	return NewFileStoreNamed(dir, bundleFileName)
}

// NewFileStoreNamed returns a FileStore rooted at dir for the given file name,
// so several independent blobs can share one directory.
func NewFileStoreNamed(dir, fileName string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("certstore: file store directory is empty")
	}
	if fileName == "" || fileName != filepath.Base(fileName) {
		return nil, fmt.Errorf("certstore: invalid file store name %q", fileName)
	}
	return &FileStore{Dir: dir, FileName: fileName}, nil
}

func (s *FileStore) path() string {
	name := s.FileName
	if name == "" {
		name = bundleFileName
	}
	return filepath.Join(s.Dir, name)
}

// Load implements Store.
func (s *FileStore) Load(ctx context.Context) (*Bundle, error) {
	data, err := s.LoadBlob(ctx)
	if err != nil {
		return nil, err
	}
	return Unmarshal(data)
}

// Save implements Store.
func (s *FileStore) Save(ctx context.Context, b *Bundle) error {
	data, err := Marshal(b)
	if err != nil {
		return err
	}
	return s.SaveBlob(ctx, data)
}

// LoadBlob implements BlobStore.
func (s *FileStore) LoadBlob(_ context.Context) ([]byte, error) {
	data, err := os.ReadFile(s.path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("certstore: read %s: %w", s.path(), err)
	}
	if len(data) == 0 {
		return nil, ErrNotFound
	}
	return data, nil
}

// SaveBlob implements BlobStore with an atomic replace.
func (s *FileStore) SaveBlob(_ context.Context, data []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("certstore: create %s: %w", s.Dir, err)
	}
	tmp, err := os.CreateTemp(s.Dir, "."+filepath.Base(s.path())+"-*.tmp")
	if err != nil {
		return fmt.Errorf("certstore: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("certstore: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("certstore: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("certstore: fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("certstore: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path()); err != nil {
		cleanup()
		return fmt.Errorf("certstore: rename into place: %w", err)
	}
	// Best effort: persist the directory entry too.
	if d, err := os.Open(s.Dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
