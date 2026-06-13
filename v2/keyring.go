// Package keyring provides a context-aware API over secure credential storage
// backends.
package keyring

import (
	"context"
	"errors"
	"fmt"
	"time"

	v1 "github.com/99designs/keyring"
)

// Backend identifies a credential storage backend.
type Backend string

// Built-in credential storage backends.
const (
	InvalidBackend       Backend = ""
	SecretServiceBackend Backend = "secret-service"
	KeychainBackend      Backend = "keychain"
	KeyCtlBackend        Backend = "keyctl"
	KWalletBackend       Backend = "kwallet"
	WinCredBackend       Backend = "wincred"
	FileBackend          Backend = "file"
	PassBackend          Backend = "pass"
)

var defaultBackendOrder = []Backend{
	WinCredBackend,
	KeychainBackend,
	SecretServiceBackend,
	KWalletBackend,
	KeyCtlBackend,
	PassBackend,
	FileBackend,
}

// Item is a credential stored in a keyring.
type Item struct {
	Key         string
	Data        []byte
	Label       string
	Description string
}

// Metadata is the non-secret data for a stored credential.
type Metadata struct {
	Key              string
	Label            string
	Description      string
	ModificationTime time.Time
}

// Keyring provides the common credential storage interface.
type Keyring interface {
	Get(context.Context, string) (Item, error)
	Set(context.Context, Item) error
	Remove(context.Context, string) error
	Keys(context.Context) ([]string, error)
}

// MetadataReader is implemented by keyrings that can read metadata without
// exposing secret data.
type MetadataReader interface {
	Metadata(context.Context, string) (Metadata, error)
}

// OpenOptions are the provider-visible options selected by Open.
type OpenOptions struct {
	ServiceName string
	Backends    []Backend
}

// Provider describes a backend implementation.
type Provider struct {
	Backend Backend
	Open    func(context.Context, OpenOptions) (Keyring, error)
}

// FallbackPolicy controls when Open should try the next provider.
type FallbackPolicy int

const (
	// FallbackOnUnavailable tries the next provider only when the current
	// provider returns ErrUnavailable.
	FallbackOnUnavailable FallbackPolicy = iota
	// FallbackOnError tries the next provider after any open error.
	FallbackOnError
)

// Stable errors returned by this package.
var (
	ErrUnavailable          = errors.New("keyring backend unavailable")
	ErrNotFound             = errors.New("keyring item not found")
	ErrAccessDenied         = errors.New("keyring access denied")
	ErrTooLarge             = errors.New("credential data exceeds backend limit")
	ErrMetadataUnsupported  = errors.New("keyring metadata unsupported")
	ErrMetadataNeedsUnlock  = errors.New("keyring metadata requires credentials")
	ErrInvalidOption        = errors.New("invalid keyring option")
	ErrNoProvider           = errors.New("keyring provider not found")
	errProviderBackendEmpty = errors.New("provider backend is empty")
	errProviderOpenNil      = errors.New("provider open function is nil")
)

// Open opens the first configured backend that is available.
func Open(ctx context.Context, opts ...Option) (Keyring, error) {
	cfg, err := newOptions(opts)
	if err != nil {
		return nil, err
	}

	providers, order := providerRegistry(cfg.providers)
	backends := cfg.backends
	if backends == nil {
		backends = availableBackends(providers, order)
	}

	openOptions := OpenOptions{
		ServiceName: cfg.serviceName,
		Backends:    append([]Backend(nil), backends...),
	}

	var unavailable error
	for _, backend := range backends {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		provider, ok := providers[backend]
		if !ok {
			unavailable = errors.Join(unavailable, ErrUnavailable, fmt.Errorf("%w: %s", ErrNoProvider, backend))
			continue
		}

		ring, err := provider.Open(ctx, openOptions)
		if err == nil {
			return ring, nil
		}

		if shouldFallback(cfg.fallbackPolicy, err) {
			unavailable = errors.Join(unavailable, fmt.Errorf("%s: %w", backend, err))
			continue
		}

		return nil, fmt.Errorf("%s: %w", backend, err)
	}

	if unavailable != nil {
		return nil, unavailable
	}
	return nil, ErrUnavailable
}

// Available returns the available backend names after applying options.
func Available(opts ...Option) ([]Backend, error) {
	cfg, err := newOptions(opts)
	if err != nil {
		return nil, err
	}
	providers, order := providerRegistry(cfg.providers)
	return availableBackends(providers, order), nil
}

// DefaultProviders returns the built-in backend providers.
func DefaultProviders() []Provider {
	available := v1.AvailableBackends()
	providers := make([]Provider, 0, len(available))
	for _, backend := range available {
		if provider, ok := defaultProviderFor(Backend(backend)); ok {
			providers = append(providers, provider)
		}
	}
	return providers
}

func defaultProviderFor(backend Backend) (Provider, bool) {
	switch backend {
	case InvalidBackend:
		return Provider{}, false
	case WinCredBackend:
		return WinCredProvider(), true
	case KeychainBackend:
		return KeychainProvider(), true
	case SecretServiceBackend:
		return SecretServiceProvider(), true
	case KWalletBackend:
		return KWalletProvider(), true
	case KeyCtlBackend:
		return KeyCtlProvider(), true
	case PassBackend:
		return PassProvider(), true
	case FileBackend:
		return FileProvider(), true
	default:
		return Provider{}, false
	}
}

func shouldFallback(policy FallbackPolicy, err error) bool {
	if policy == FallbackOnError {
		return true
	}
	return errors.Is(err, ErrUnavailable)
}

func providerRegistry(providers []Provider) (map[Backend]Provider, []Backend) {
	out := make(map[Backend]Provider, len(providers))
	order := make([]Backend, 0, len(defaultBackendOrder)+len(providers))

	order = append(order, defaultBackendOrder...)

	for _, provider := range providers {
		if _, ok := out[provider.Backend]; !ok && !isDefaultBackend(provider.Backend) {
			order = append(order, provider.Backend)
		}
		out[provider.Backend] = provider
	}

	return out, order
}

func availableBackends(providers map[Backend]Provider, order []Backend) []Backend {
	out := make([]Backend, 0, len(providers))
	for _, backend := range order {
		if provider, ok := providers[backend]; ok && provider.Backend != InvalidBackend && provider.Open != nil {
			out = append(out, backend)
		}
	}
	return out
}

func isDefaultBackend(backend Backend) bool {
	for _, existing := range defaultBackendOrder {
		if backend == existing {
			return true
		}
	}
	return false
}

func mapError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, v1.ErrNoAvailImpl):
		return errors.Join(ErrUnavailable, err)
	case errors.Is(err, v1.ErrKeyNotFound):
		return errors.Join(ErrNotFound, err)
	case errors.Is(err, v1.ErrAccessDenied):
		return errors.Join(ErrAccessDenied, err)
	case errors.Is(err, v1.ErrCredentialTooLarge):
		return errors.Join(ErrTooLarge, err)
	case errors.Is(err, v1.ErrMetadataNotSupported):
		return errors.Join(ErrMetadataUnsupported, err)
	case errors.Is(err, v1.ErrMetadataNeedsCredentials):
		return errors.Join(ErrMetadataNeedsUnlock, err)
	default:
		return err
	}
}
