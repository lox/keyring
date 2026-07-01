package keyring

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

var testExternalBackend Backend = "test-external"

func TestOpenUsesExternalProvider(t *testing.T) {
	ctx := context.Background()
	called := false

	ring, err := Open(ctx,
		WithServiceName("external-service"),
		WithBackends(testExternalBackend),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, opts OpenOptions) (Keyring, error) {
				called = true
				return newArrayKeyring(ctx, []Item{{
					Key:  opts.ServiceName,
					Data: []byte("opened"),
				}}), nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !called {
		t.Fatal("expected external provider to be called")
	}

	item, err := ring.Get(ctx, "external-service")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(item.Data) != "opened" {
		t.Fatalf("expected provider-backed item, got %q", item.Data)
	}
}

func TestOpenOverridesBuiltinBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	ring, err := Open(ctx,
		WithServiceName("override"),
		WithBackends(FileBackend),
		WithProvider(FileProvider(
			FileDir(dir),
			FilePrompt(FixedStringPrompt("test-pass")),
		)),
		WithProvider(Provider{
			Backend: FileBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := ring.Set(ctx, Item{Key: "llamas", Data: []byte("great")}); err != nil {
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

func TestOpenCanWrapBuiltinFileBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rawFile := FileProvider(
		FileDir(dir),
		FilePrompt(FixedStringPrompt("test-pass")),
	)

	ring, err := Open(ctx,
		WithServiceName("file-wrapper"),
		WithBackends(FileBackend),
		WithProvider(Provider{
			Backend: FileBackend,
			Open: func(ctx context.Context, opts OpenOptions) (Keyring, error) {
				ring, err := rawFile.Open(ctx, opts)
				if err != nil {
					return nil, err
				}
				return testEncodedKeyring{inner: ring}, nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	key := `token:default:user@example.com/<>:"\|?*%`
	if err := ring.Set(ctx, Item{Key: key, Data: []byte("secret")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	item, err := ring.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if item.Key != key || string(item.Data) != "secret" {
		t.Fatalf("unexpected item: key=%q data=%q", item.Key, item.Data)
	}

	keys, err := ring.Keys(ctx)
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

func TestBackendAdapterClosesBackend(t *testing.T) {
	backend := &testClosingBackend{}
	if err := (backendAdapter{ring: backend}).Close(); err != nil {
		t.Fatal(err)
	}
	if !backend.closed {
		t.Fatal("expected adapter to close backend")
	}
}

func TestOpenFallsBackWhenFileProviderIsNotConfigured(t *testing.T) {
	ctx := context.Background()

	ring, err := Open(ctx,
		WithBackends(FileBackend, testExternalBackend),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ring == nil {
		t.Fatal("expected fallback ring")
	}
}

type testClosingBackend struct {
	closed bool
}

func (k *testClosingBackend) Get(string) (Item, error) {
	return Item{}, ErrNotFound
}

func (k *testClosingBackend) GetMetadata(string) (Metadata, error) {
	return Metadata{}, ErrMetadataUnsupported
}

func (k *testClosingBackend) Set(Item) error {
	return nil
}

func (k *testClosingBackend) Remove(string) error {
	return nil
}

func (k *testClosingBackend) Keys() ([]string, error) {
	return nil, nil
}

func (k *testClosingBackend) Close() error {
	k.closed = true
	return nil
}

func TestOpenRejectsFileProviderWithoutPrompt(t *testing.T) {
	_, err := Open(context.Background(),
		WithBackends(FileBackend),
		WithProvider(FileProvider(FileDir(t.TempDir()))),
	)
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected invalid file backend, got %v", err)
	}
}

func TestAvailableIncludesExternalProviders(t *testing.T) {
	got, err := Available(WithProviders(
		Provider{Backend: FileBackend, Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) { return newArrayKeyring(ctx, nil), nil }},
		Provider{Backend: testExternalBackend, Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) { return newArrayKeyring(ctx, nil), nil }},
	))
	if err != nil {
		t.Fatalf("Available: %v", err)
	}

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

func TestAvailableHonorsConfiguredBackends(t *testing.T) {
	got, err := Available(
		WithBackends(testExternalBackend),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	if !slices.Equal(got, []Backend{testExternalBackend}) {
		t.Fatalf("expected configured backend only, got %v", got)
	}
}

func TestOpenRejectsInvalidProvider(t *testing.T) {
	_, err := Open(context.Background(),
		WithBackends(testExternalBackend),
		WithProvider(Provider{Backend: testExternalBackend}),
	)
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected invalid option, got %v", err)
	}
	if !strings.Contains(err.Error(), "open function is nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenFallsBackOnUnavailable(t *testing.T) {
	ring, err := Open(context.Background(),
		WithBackends("missing", testExternalBackend),
		WithProvider(Provider{
			Backend: "missing",
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return nil, ErrUnavailable
			},
		}),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ring == nil {
		t.Fatal("expected fallback ring")
	}
}

func TestOpenStopsOnNonUnavailableByDefault(t *testing.T) {
	errDenied := errors.New("denied")
	_, err := Open(context.Background(),
		WithBackends("denied", testExternalBackend),
		WithProvider(Provider{
			Backend: "denied",
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return nil, errDenied
			},
		}),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if !errors.Is(err, errDenied) {
		t.Fatalf("expected denied error, got %v", err)
	}
}

func TestBuiltinProviderStopsOnNonUnavailableOpenError(t *testing.T) {
	backend := Backend("test-builtin-open-error")
	errOpen := errors.New("bad config")
	calledFallback := false

	oldOpener, hadOpener := supportedBackends[backend]
	supportedBackends[backend] = func(Config) (backendKeyring, error) {
		return nil, errOpen
	}
	t.Cleanup(func() {
		if hadOpener {
			supportedBackends[backend] = oldOpener
			return
		}
		delete(supportedBackends, backend)
	})

	_, err := Open(context.Background(),
		WithBackends(backend, testExternalBackend),
		WithProvider(builtinProvider(backend, nil)),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				calledFallback = true
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if !errors.Is(err, errOpen) {
		t.Fatalf("expected opener error, got %v", err)
	}
	if calledFallback {
		t.Fatal("expected non-unavailable opener error to stop fallback")
	}
}

func TestOpenCanFallbackOnAnyError(t *testing.T) {
	ring, err := Open(context.Background(),
		WithFallbackPolicy(FallbackOnError),
		WithBackends("denied", testExternalBackend),
		WithProvider(Provider{
			Backend: "denied",
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return nil, errors.New("denied")
			},
		}),
		WithProvider(Provider{
			Backend: testExternalBackend,
			Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
				return newArrayKeyring(ctx, nil), nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ring == nil {
		t.Fatal("expected fallback ring")
	}
}

type testEncodedKeyring struct {
	inner Keyring
}

func (k testEncodedKeyring) Get(ctx context.Context, key string) (Item, error) {
	item, err := k.inner.Get(ctx, testEncodeKey(key))
	if err != nil {
		return Item{}, err
	}
	item.Key = key
	return item, nil
}

func (k testEncodedKeyring) Metadata(ctx context.Context, key string) (Metadata, error) {
	reader, ok := k.inner.(MetadataReader)
	if !ok {
		return Metadata{}, ErrMetadataUnsupported
	}
	metadata, err := reader.Metadata(ctx, testEncodeKey(key))
	if err != nil {
		return Metadata{}, err
	}
	if metadata.Item != nil {
		metadata.Key = key
	}
	return metadata, nil
}

func (k testEncodedKeyring) Set(ctx context.Context, item Item) error {
	item.Key = testEncodeKey(item.Key)
	return k.inner.Set(ctx, item)
}

func (k testEncodedKeyring) Remove(ctx context.Context, key string) error {
	return k.inner.Remove(ctx, testEncodeKey(key))
}

func (k testEncodedKeyring) Keys(ctx context.Context) ([]string, error) {
	keys, err := k.inner.Keys(ctx)
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
