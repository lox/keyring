// Package keyring provides a uniform API over a range of desktop credential storage engines.
package keyring

import (
	"errors"
	"fmt"
	"log"
	"time"
)

// BackendType is an identifier for a credential storage service.
type BackendType string

// All currently supported secure storage backends.
const (
	InvalidBackend       BackendType = ""
	SecretServiceBackend BackendType = "secret-service"
	KeychainBackend      BackendType = "keychain"
	KeyCtlBackend        BackendType = "keyctl"
	KWalletBackend       BackendType = "kwallet"
	WinCredBackend       BackendType = "wincred"
	FileBackend          BackendType = "file"
	PassBackend          BackendType = "pass"
)

// This order makes sure the OS-specific backends
// are picked over the more generic backends.
var backendOrder = []BackendType{
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

var supportedBackends = map[BackendType]opener{}

// AvailableBackends provides a slice of all available backend keys on the current OS.
func AvailableBackends() []BackendType {
	return AvailableBackendsWithProviders()
}

// AvailableBackendsWithProviders provides a slice of available backend keys,
// including the supplied external providers. Invalid providers are ignored.
func AvailableBackendsWithProviders(providers ...Provider) []BackendType {
	backends, order := backendRegistry(validProviders(providers))
	return availableBackends(backends, order)
}

func availableBackends(backends map[BackendType]opener, order []BackendType) []BackendType {
	b := []BackendType{}
	for _, k := range order {
		_, ok := backends[k]
		if ok {
			b = append(b, k)
		}
	}
	return b
}

// Opener opens a concrete keyring backend.
type Opener func(cfg Config) (Keyring, error)

type opener = Opener

// Provider describes a backend implementation that can be supplied by callers.
//
// Providers passed to OpenWithProviders are local to that call. If a provider
// uses the same Backend as a built-in backend, it replaces the built-in opener
// for that call.
type Provider struct {
	Backend BackendType
	Open    Opener
}

var errKeychainSynchronizableWithCustomKeychain = errors.New("keychain synchronizable is not supported with custom keychains")

// Open will open a specific keyring backend.
func Open(cfg Config) (Keyring, error) {
	return OpenWithProviders(cfg)
}

// OpenWithProviders opens a keyring backend using the built-in backends plus
// any caller-supplied providers.
//
// Providers are tried according to Config.AllowedBackends. When AllowedBackends
// is nil, built-in backends retain their normal order and new external backends
// are tried after the built-ins.
func OpenWithProviders(cfg Config, providers ...Provider) (Keyring, error) {
	backends, order, err := backendRegistryForOpen(providers)
	if err != nil {
		return nil, err
	}
	if cfg.AllowedBackends == nil {
		cfg.AllowedBackends = availableBackends(backends, order)
	}
	debugf("Considering backends: %v", cfg.AllowedBackends)
	for _, backend := range cfg.AllowedBackends {
		if opener, ok := backends[backend]; ok {
			openBackend, err := opener(cfg)
			if err != nil {
				debugf("Failed backend %s: %s", backend, err)
				if errors.Is(err, errKeychainSynchronizableWithCustomKeychain) {
					return nil, err
				}
				continue
			}
			return openBackend, nil
		}
	}
	return nil, ErrNoAvailImpl
}

func backendRegistryForOpen(providers []Provider) (map[BackendType]opener, []BackendType, error) {
	for _, provider := range providers {
		if provider.Backend == InvalidBackend {
			return nil, nil, fmt.Errorf("invalid keyring provider: backend is empty")
		}
		if provider.Open == nil {
			return nil, nil, fmt.Errorf("invalid keyring provider %q: opener is nil", provider.Backend)
		}
	}

	backends, order := backendRegistry(providers)
	return backends, order, nil
}

func validProviders(providers []Provider) []Provider {
	valid := make([]Provider, 0, len(providers))
	for _, provider := range providers {
		if provider.Backend == InvalidBackend || provider.Open == nil {
			continue
		}
		valid = append(valid, provider)
	}
	return valid
}

func backendRegistry(providers []Provider) (map[BackendType]opener, []BackendType) {
	backends := make(map[BackendType]opener, len(supportedBackends)+len(providers))
	order := make([]BackendType, 0, len(backendOrder)+len(providers))

	for _, backend := range backendOrder {
		if opener, ok := supportedBackends[backend]; ok {
			backends[backend] = opener
			order = append(order, backend)
		}
	}

	for _, provider := range providers {
		if _, ok := backends[provider.Backend]; !ok {
			order = append(order, provider.Backend)
		}
		backends[provider.Backend] = provider.Open
	}

	return backends, order
}

// Item is a thing stored on the keyring.
type Item struct {
	Key         string
	Data        []byte
	Label       string
	Description string

	// Backend specific config
	KeychainNotTrustApplication bool
	KeychainNotSynchronizable   bool
}

// Metadata is information about a thing stored on the keyring; retrieving
// metadata must not require authentication.  The embedded Item should be
// filled in with an empty Data field.
// It's allowed for Item to be a nil pointer, indicating that all we
// have is the timestamps.
type Metadata struct {
	*Item
	ModificationTime time.Time
}

// Keyring provides the uniform interface over the underlying backends.
type Keyring interface {
	// Returns an Item matching the key or ErrKeyNotFound
	Get(key string) (Item, error)
	// Returns the non-secret parts of an Item
	GetMetadata(key string) (Metadata, error)
	// Stores an Item on the keyring
	Set(item Item) error
	// Removes the item with matching key
	Remove(key string) error
	// Provides a slice of all keys stored on the keyring
	Keys() ([]string, error)
}

// ErrNoAvailImpl is returned by Open when a backend cannot be found.
var ErrNoAvailImpl = errors.New("specified keyring backend not available")

// ErrKeyNotFound is returned by Keyring Get when the item is not on the keyring.
var ErrKeyNotFound = errors.New("specified item could not be found in the keyring")

// ErrAccessDenied is returned when the backend denies access or the user
// cancels an authentication prompt. Returned errors may also wrap the
// backend-specific error so callers can inspect the underlying platform error.
var ErrAccessDenied = errors.New("keyring access denied")

// ErrCredentialTooLarge is returned when a backend cannot store the item's data
// because it exceeds that backend's credential size limit.
var ErrCredentialTooLarge = errors.New("credential data exceeds backend limit")

// ErrMetadataNeedsCredentials is returned when Metadata is called against a
// backend which requires credentials even to see metadata.
var ErrMetadataNeedsCredentials = errors.New("keyring backend requires credentials for metadata access")

// ErrMetadataNotSupported is returned when Metadata is not available for the backend.
var ErrMetadataNotSupported = errors.New("keyring backend does not support metadata access")

var (
	// Debug specifies whether to print debugging output.
	Debug bool
)

func debugf(pattern string, args ...interface{}) {
	if Debug {
		log.Printf("[keyring] "+pattern, args...)
	}
}
