package keyring

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	jose "github.com/dvsekhvalnov/jose2go"
	"github.com/mtibben/percent"
)

const fileKeyDir = "_keyring_v1"

var filenameEscape = func(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

var filenameUnescape = func(s string) string {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return legacyFilenameUnescape(s)
	}

	decoded := string(raw)
	if filenameEscape(decoded) != s {
		return legacyFilenameUnescape(s)
	}
	return decoded
}

var legacyFilenameEscape = func(s string) string {
	return percent.Encode(s, "/")
}
var legacyFilenameUnescape = percent.Decode

type fileKeyring struct {
	dir          string
	passwordFunc PromptFunc
	password     string
}

func (k *fileKeyring) Get(ctx context.Context, key string) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	return k.get(key)
}

func (k *fileKeyring) Set(ctx context.Context, item Item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return k.set(item)
}

func (k *fileKeyring) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return k.remove(key)
}

func (k *fileKeyring) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return k.keys()
}

func (k *fileKeyring) Metadata(ctx context.Context, key string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	return k.metadata(key)
}

func (k *fileKeyring) resolveDir() (string, error) {
	if k.dir == "" {
		return "", fmt.Errorf("no directory provided for file keyring")
	}

	dir, err := ExpandTilde(k.dir)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		return dir, os.MkdirAll(dir, 0700)
	case err != nil:
		return "", err
	case !info.IsDir():
		return "", fmt.Errorf("%s is a file, not a directory", dir)
	}

	return dir, nil
}

func (k *fileKeyring) unlock() error {
	dir, err := k.resolveDir()
	if err != nil {
		return err
	}

	if k.password == "" {
		pwd, err := k.passwordFunc(fmt.Sprintf("Enter passphrase to unlock %q", dir))
		if err != nil {
			return err
		}
		k.password = pwd
	}

	return nil
}

func (k *fileKeyring) get(key string) (Item, error) {
	filename, err := k.filename(key)
	if err != nil {
		return Item{}, err
	}

	bytes, err := os.ReadFile(filename)
	if fileNotFound(err) {
		bytes, err = k.readLegacy(key)
	}
	if fileNotFound(err) {
		return Item{}, ErrKeyNotFound
	}
	if err != nil {
		return Item{}, err
	}

	if err = k.unlock(); err != nil {
		return Item{}, err
	}

	payload, _, err := jose.Decode(string(bytes), k.password)
	if err != nil {
		return Item{}, err
	}

	var decoded Item
	err = json.Unmarshal([]byte(payload), &decoded)

	return decoded, err
}

func (k *fileKeyring) metadata(key string) (Metadata, error) {
	filename, err := k.filename(key)
	if err != nil {
		return Metadata{}, err
	}

	stat, err := os.Stat(filename)
	if fileNotFound(err) {
		stat, err = k.statLegacy(key)
	}
	if fileNotFound(err) {
		return Metadata{}, ErrKeyNotFound
	}
	if err != nil {
		return Metadata{}, err
	}

	// For the File provider, all internal data is encrypted, not just the
	// credentials.  Thus we only have the timestamps.  Return a nil *Item.
	//
	// If we want to change this ... how portable are extended file attributes
	// these days?  Would it break user expectations of the security model to
	// leak data into those?  I'm hesitant to do so.

	return Metadata{
		ModificationTime: stat.ModTime(),
	}, nil
}

func (k *fileKeyring) set(i Item) error {
	bytes, err := json.Marshal(i)
	if err != nil {
		return err
	}

	if err = k.unlock(); err != nil {
		return err
	}

	token, err := jose.Encrypt(string(bytes), jose.PBES2_HS256_A128KW, jose.A256GCM, k.password,
		jose.Headers(map[string]interface{}{
			"created": time.Now().String(),
		}))
	if err != nil {
		return err
	}

	if _, err := k.storageDir(); err != nil {
		return err
	}

	filename, err := k.filename(i.Key)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(token), 0600)
}

func (k *fileKeyring) filename(key string) (string, error) {
	dir, err := k.resolveDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, fileKeyDir, filenameEscape(key)), nil
}

func (k *fileKeyring) storageDir() (string, error) {
	dir, err := k.resolveDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, fileKeyDir)

	info, err := os.Stat(dir)
	switch {
	case os.IsNotExist(err):
		return dir, os.MkdirAll(dir, 0700)
	case err != nil:
		return "", err
	case !info.IsDir():
		return "", fmt.Errorf("%s is a file, not a directory", dir)
	}

	return dir, nil
}

func (k *fileKeyring) legacyFilename(key string) (string, error) {
	dir, err := k.resolveDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, legacyFilenameEscape(key)), nil
}

func (k *fileKeyring) readLegacy(key string) ([]byte, error) {
	filename, err := k.legacyFilename(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filename)
}

func (k *fileKeyring) statLegacy(key string) (os.FileInfo, error) {
	filename, err := k.legacyFilename(key)
	if err != nil {
		return nil, err
	}
	return os.Stat(filename)
}

func (k *fileKeyring) remove(key string) error {
	filename, err := k.filename(key)
	if err != nil {
		return err
	}

	err = os.Remove(filename)
	legacyErr := k.removeLegacy(key)

	if (err == nil || fileNotFound(err)) && (legacyErr == nil || fileNotFound(legacyErr)) {
		if fileNotFound(err) && fileNotFound(legacyErr) {
			return ErrKeyNotFound
		}
		return nil
	}
	if err != nil && !fileNotFound(err) {
		return err
	}
	return legacyErr
}

func (k *fileKeyring) removeLegacy(key string) error {
	filename, err := k.legacyFilename(key)
	if err != nil {
		return err
	}
	return os.Remove(filename)
}

func fileNotFound(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	if errno == syscall.ENOTDIR {
		return true
	}
	return runtime.GOOS == "windows" && errno == syscall.Errno(0x7B)
}

func (k *fileKeyring) keys() ([]string, error) {
	dir, err := k.resolveDir()
	if err != nil {
		return nil, err
	}

	var keys []string
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f.IsDir() && f.Name() == fileKeyDir {
			continue
		}
		keys = append(keys, legacyFilenameUnescape(f.Name()))
	}

	storageDir := filepath.Join(dir, fileKeyDir)
	info, err := os.Stat(storageDir)
	if fileNotFound(err) {
		sort.Strings(keys)
		return dedupeSortedStrings(keys), nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		sort.Strings(keys)
		return dedupeSortedStrings(keys), nil
	}

	files, err = os.ReadDir(storageDir)
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		keys = append(keys, filenameUnescape(f.Name()))
	}

	sort.Strings(keys)
	return dedupeSortedStrings(keys), nil
}

func dedupeSortedStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
