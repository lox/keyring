package keyring

import (
	"context"
	"errors"
	"slices"
	"testing"
)

const testBackend Backend = "test"

func TestOpenUsesProviderOption(t *testing.T) {
	ctx := context.Background()
	called := false

	ring, err := Open(ctx,
		WithServiceName("svc"),
		WithBackends(testBackend),
		WithProvider(Provider{
			Backend: testBackend,
			Open: func(_ context.Context, opts OpenOptions) (Keyring, error) {
				called = true
				if opts.ServiceName != "svc" {
					t.Fatalf("service name = %q, want svc", opts.ServiceName)
				}
				return &memoryKeyring{items: map[string]Item{
					"svc": {Key: "svc", Data: []byte("ok")},
				}}, nil
			},
		}),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !called {
		t.Fatal("provider was not called")
	}

	item, err := ring.Get(ctx, "svc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(item.Data) != "ok" {
		t.Fatalf("unexpected item data %q", item.Data)
	}
}

func TestOpenFallsBackOnUnavailable(t *testing.T) {
	ctx := context.Background()
	ring, err := Open(ctx,
		WithBackends("missing", testBackend),
		WithProvider(Provider{
			Backend: "missing",
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return nil, ErrUnavailable
			},
		}),
		WithProvider(Provider{
			Backend: testBackend,
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return &memoryKeyring{}, nil
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

func TestOpenTreatsMissingProviderAsUnavailable(t *testing.T) {
	_, err := Open(context.Background(), WithBackends(testBackend))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable error, got %v", err)
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected no provider error, got %v", err)
	}
}

func TestOpenStopsOnNonUnavailableByDefault(t *testing.T) {
	errDenied := errors.New("denied")
	_, err := Open(context.Background(),
		WithBackends("denied", testBackend),
		WithProvider(Provider{
			Backend: "denied",
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return nil, errDenied
			},
		}),
		WithProvider(Provider{
			Backend: testBackend,
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return &memoryKeyring{}, nil
			},
		}),
	)
	if !errors.Is(err, errDenied) {
		t.Fatalf("expected denied error, got %v", err)
	}
}

func TestOpenCanFallbackOnAnyError(t *testing.T) {
	ring, err := Open(context.Background(),
		WithFallbackPolicy(FallbackOnError),
		WithBackends("denied", testBackend),
		WithProvider(Provider{
			Backend: "denied",
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return nil, errors.New("denied")
			},
		}),
		WithProvider(Provider{
			Backend: testBackend,
			Open: func(context.Context, OpenOptions) (Keyring, error) {
				return &memoryKeyring{}, nil
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

func TestFileProviderRoundTrip(t *testing.T) {
	ctx := context.Background()
	ring, err := Open(ctx,
		WithServiceName("file-test"),
		WithBackends(FileBackend),
		WithProvider(FileProvider(
			FileDir(t.TempDir()),
			FilePrompt(FixedStringPrompt("test-pass")),
		)),
	)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := ring.Set(ctx, Item{Key: "token:default:user@example.com", Data: []byte("secret")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	item, err := ring.Get(ctx, "token:default:user@example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(item.Data) != "secret" {
		t.Fatalf("unexpected data %q", item.Data)
	}
}

func TestAvailableIncludesExternalProvider(t *testing.T) {
	backends, err := Available(WithProvider(Provider{
		Backend: testBackend,
		Open: func(context.Context, OpenOptions) (Keyring, error) {
			return &memoryKeyring{}, nil
		},
	}))
	if err != nil {
		t.Fatalf("Available: %v", err)
	}
	if !slices.Contains(backends, testBackend) {
		t.Fatalf("expected %q in %v", testBackend, backends)
	}
}

func TestInvalidProviderOption(t *testing.T) {
	_, err := Open(context.Background(), WithProvider(Provider{Backend: testBackend}))
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected invalid option, got %v", err)
	}
}

type memoryKeyring struct {
	items map[string]Item
}

func (k *memoryKeyring) Get(_ context.Context, key string) (Item, error) {
	if item, ok := k.items[key]; ok {
		return item, nil
	}
	return Item{}, ErrNotFound
}

func (k *memoryKeyring) Set(_ context.Context, item Item) error {
	if k.items == nil {
		k.items = make(map[string]Item)
	}
	k.items[item.Key] = item
	return nil
}

func (k *memoryKeyring) Remove(_ context.Context, key string) error {
	delete(k.items, key)
	return nil
}

func (k *memoryKeyring) Keys(context.Context) ([]string, error) {
	keys := make([]string, 0, len(k.items))
	for key := range k.items {
		keys = append(keys, key)
	}
	return keys, nil
}
