// Package keyring provides a context-aware API over credential storage
// providers.
package keyring

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Backend identifies a credential storage backend.
type Backend string

// BackendType is an alias for Backend for callers migrating from the previous
// API.
type BackendType = Backend

// Well-known backend names.
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

// Item is a credential stored in a keyring.
type Item struct {
	Key         string
	Data        []byte
	Label       string
	Description string

	// Backend specific config.
	KeychainNotTrustApplication bool
	KeychainNotSynchronizable   bool
}

// Metadata is the non-secret data for a stored credential. Retrieving metadata
// must not require authentication. The embedded Item should be filled in with an
// empty Data field. Item may be nil when the backend can only return timestamps.
type Metadata struct {
	*Item
	ModificationTime time.Time
}

// Keyring provides the common credential storage interface. Keyrings that own
// external resources may also implement io.Closer.
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

// ErrNoAvailImpl is returned when a backend cannot be found.
var ErrNoAvailImpl = ErrUnavailable

// ErrKeyNotFound is returned when the item is not on the keyring.
var ErrKeyNotFound = ErrNotFound

// ErrCredentialTooLarge is returned when the backend cannot store an item's
// data because it exceeds that backend's credential size limit.
var ErrCredentialTooLarge = ErrTooLarge

// ErrMetadataNeedsCredentials is returned when metadata requires credentials.
var ErrMetadataNeedsCredentials = ErrMetadataNeedsUnlock

// ErrMetadataNotSupported is returned when metadata is not available.
var ErrMetadataNotSupported = ErrMetadataUnsupported

// Open opens the first configured provider that is available.
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

		debugf("Failed backend %s: %s", backend, err)
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
	if cfg.backends != nil {
		return availableBackends(providers, cfg.backends), nil
	}
	return availableBackends(providers, order), nil
}

func shouldFallback(policy FallbackPolicy, err error) bool {
	if policy == FallbackOnError {
		return true
	}
	return errors.Is(err, ErrUnavailable)
}

func providerRegistry(providers []Provider) (map[Backend]Provider, []Backend) {
	out := make(map[Backend]Provider, len(providers))
	order := make([]Backend, 0, len(providers))

	for _, provider := range providers {
		if _, ok := out[provider.Backend]; !ok {
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

// Debug specifies whether to print debugging output.
var Debug bool

func debugf(pattern string, args ...interface{}) {
	if Debug {
		log.Printf("[keyring] "+pattern, args...)
	}
}
