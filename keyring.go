// Package keyring provides a context-aware API over desktop credential storage
// backends.
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

// All currently supported secure storage backends.
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

// This order makes sure the OS-specific backends are picked over the more
// generic backends.
var backendOrder = []Backend{
	// Windows
	WinCredBackend,
	// MacOS
	KeychainBackend,
	// Linux
	SecretServiceBackend,
	KWalletBackend,
	KeyCtlBackend,
	// General
	PassBackend,
	FileBackend,
}

var supportedBackends = map[Backend]backendOpener{}

type backendOpener func(cfg Config) (backendKeyring, error)

type opener = backendOpener

type backendKeyring interface {
	Get(string) (Item, error)
	GetMetadata(string) (Metadata, error)
	Set(Item) error
	Remove(string) error
	Keys() ([]string, error)
}

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

var errKeychainSynchronizableWithCustomKeychain = errors.New("keychain synchronizable is not supported with custom keychains")

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

// AvailableBackends provides a slice of all available backend keys on the
// current OS.
func AvailableBackends() []Backend {
	backends, err := Available()
	if err != nil {
		return nil
	}
	return backends
}

// DefaultProviders returns the built-in backend providers.
func DefaultProviders() []Provider {
	providers := make([]Provider, 0, len(supportedBackends))
	for _, backend := range backendOrder {
		if _, ok := supportedBackends[backend]; ok {
			providers = append(providers, defaultProviderFor(backend))
		}
	}
	return providers
}

func defaultProviderFor(backend Backend) Provider {
	switch backend {
	case InvalidBackend:
		return Provider{}
	case WinCredBackend:
		return WinCredProvider()
	case KeychainBackend:
		return KeychainProvider()
	case SecretServiceBackend:
		return SecretServiceProvider()
	case KWalletBackend:
		return KWalletProvider()
	case KeyCtlBackend:
		return KeyCtlProvider()
	case PassBackend:
		return PassProvider()
	case FileBackend:
		return FileProvider()
	default:
		return Provider{}
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
	order := make([]Backend, 0, len(backendOrder)+len(providers))

	order = append(order, backendOrder...)

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
	for _, existing := range backendOrder {
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
	case errors.Is(err, ErrNoAvailImpl):
		return errors.Join(ErrUnavailable, err)
	case errors.Is(err, ErrKeyNotFound):
		return errors.Join(ErrNotFound, err)
	case errors.Is(err, ErrAccessDenied):
		return errors.Join(ErrAccessDenied, err)
	case errors.Is(err, ErrCredentialTooLarge):
		return errors.Join(ErrTooLarge, err)
	case errors.Is(err, ErrMetadataNotSupported):
		return errors.Join(ErrMetadataUnsupported, err)
	case errors.Is(err, ErrMetadataNeedsCredentials):
		return errors.Join(ErrMetadataNeedsUnlock, err)
	default:
		return err
	}
}

// Debug specifies whether to print debugging output.
var Debug bool

func debugf(pattern string, args ...interface{}) {
	if Debug {
		log.Printf("[keyring] "+pattern, args...)
	}
}
