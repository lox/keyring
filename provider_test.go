package keyring

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
)

const testExternalBackend BackendType = "test-external"

func TestOpenWithProvidersUsesExternalProvider(t *testing.T) {
	called := false
	ring, err := OpenWithProviders(Config{
		AllowedBackends: []BackendType{testExternalBackend},
		ServiceName:     "external-service",
	}, Provider{
		Backend: testExternalBackend,
		Open: func(cfg Config) (Keyring, error) {
			called = true
			return NewArrayKeyring([]Item{{
				Key:  cfg.ServiceName,
				Data: []byte("opened"),
			}}), nil
		},
	})
	if err != nil {
		t.Fatalf("OpenWithProviders: %v", err)
	}
	if !called {
		t.Fatal("expected external provider to be called")
	}

	item, err := ring.Get("external-service")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(item.Data) != "opened" {
		t.Fatalf("expected provider-backed item, got %q", item.Data)
	}
}

func TestOpenWithProvidersOverridesBuiltinBackend(t *testing.T) {
	dir := t.TempDir()
	ring, err := OpenWithProviders(Config{
		AllowedBackends:  []BackendType{FileBackend},
		FileDir:          dir,
		FilePasswordFunc: FixedStringPrompt("test-pass"),
	}, Provider{
		Backend: FileBackend,
		Open: func(Config) (Keyring, error) {
			return NewArrayKeyring(nil), nil
		},
	})
	if err != nil {
		t.Fatalf("OpenWithProviders: %v", err)
	}

	if err := ring.Set(Item{Key: "llamas", Data: []byte("great")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected override provider to avoid file backend writes, got %d entries", len(entries))
	}
}

func TestOpenWithProvidersCanWrapBuiltinFileBackend(t *testing.T) {
	dir := t.TempDir()
	ring, err := OpenWithProviders(Config{
		AllowedBackends:  []BackendType{FileBackend},
		FileDir:          dir,
		FilePasswordFunc: FixedStringPrompt("test-pass"),
	}, Provider{
		Backend: FileBackend,
		Open: func(cfg Config) (Keyring, error) {
			ring, err := Open(cfg)
			if err != nil {
				return nil, err
			}
			return testEncodedKeyring{inner: ring}, nil
		},
	})
	if err != nil {
		t.Fatalf("OpenWithProviders: %v", err)
	}

	key := `token:default:user@example.com/<>:"\|?*%`
	if err := ring.Set(Item{Key: key, Data: []byte("secret")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	item, err := ring.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if item.Key != key || string(item.Data) != "secret" {
		t.Fatalf("unexpected item: key=%q data=%q", item.Key, item.Data)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("expected decoded key %q, got %v", key, keys)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one keyring file, got %d", len(entries))
	}
	if name := entries[0].Name(); strings.Contains(name, "token:") || strings.ContainsAny(name, `<>:"/\|?*%`) {
		t.Fatalf("expected encoded keyring filename, got %q", name)
	}
}

func TestAvailableBackendsWithProvidersIncludesExternalProviders(t *testing.T) {
	got := AvailableBackendsWithProviders(
		Provider{Backend: FileBackend, Open: func(Config) (Keyring, error) { return NewArrayKeyring(nil), nil }},
		Provider{Backend: testExternalBackend, Open: func(Config) (Keyring, error) { return NewArrayKeyring(nil), nil }},
	)

	fileCount := 0
	foundExternal := false
	for _, backend := range got {
		if backend == FileBackend {
			fileCount++
		}
		if backend == testExternalBackend {
			foundExternal = true
		}
	}
	if fileCount != 1 {
		t.Fatalf("expected FileBackend once, got %d in %v", fileCount, got)
	}
	if !foundExternal {
		t.Fatalf("expected external backend in %v", got)
	}
}

func TestOpenWithProvidersRejectsInvalidProvider(t *testing.T) {
	_, err := OpenWithProviders(Config{
		AllowedBackends: []BackendType{testExternalBackend},
	}, Provider{Backend: testExternalBackend})
	if err == nil {
		t.Fatal("expected invalid provider error")
	}
	if !strings.Contains(err.Error(), "opener is nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type testEncodedKeyring struct {
	inner Keyring
}

func (k testEncodedKeyring) Get(key string) (Item, error) {
	item, err := k.inner.Get(testEncodeKey(key))
	if err != nil {
		return Item{}, err
	}
	item.Key = key
	return item, nil
}

func (k testEncodedKeyring) GetMetadata(key string) (Metadata, error) {
	metadata, err := k.inner.GetMetadata(testEncodeKey(key))
	if err != nil {
		return Metadata{}, err
	}
	if metadata.Item != nil {
		metadata.Key = key
	}
	return metadata, nil
}

func (k testEncodedKeyring) Set(item Item) error {
	item.Key = testEncodeKey(item.Key)
	return k.inner.Set(item)
}

func (k testEncodedKeyring) Remove(key string) error {
	return k.inner.Remove(testEncodeKey(key))
}

func (k testEncodedKeyring) Keys() ([]string, error) {
	keys, err := k.inner.Keys()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		decoded, err := testDecodeKey(key)
		if err != nil {
			return nil, err
		}
		out = append(out, decoded)
	}
	return out, nil
}

func testEncodeKey(key string) string {
	return "test_key_" + base64.RawURLEncoding.EncodeToString([]byte(key))
}

func testDecodeKey(key string) (string, error) {
	encoded, ok := strings.CutPrefix(key, "test_key_")
	if !ok {
		return "", errors.New("missing test key prefix")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
