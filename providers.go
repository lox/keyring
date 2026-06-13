package keyring

import (
	"context"
	"errors"
	"fmt"
)

// FileOption configures the built-in encrypted file provider.
type FileOption func(*fileConfig)

type fileConfig struct {
	dir    string
	prompt PromptFunc
}

// FileDir sets the encrypted file backend directory.
func FileDir(dir string) FileOption {
	return func(cfg *fileConfig) { cfg.dir = dir }
}

// FilePrompt sets the encrypted file backend password prompt.
func FilePrompt(prompt PromptFunc) FileOption {
	return func(cfg *fileConfig) { cfg.prompt = prompt }
}

// FileProvider returns the built-in encrypted file provider.
func FileProvider(opts ...FileOption) Provider {
	cfg := fileConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(FileBackend, func(backendCfg *Config) {
		backendCfg.FileDir = cfg.dir
		if cfg.prompt != nil {
			backendCfg.FilePasswordFunc = cfg.prompt
		}
	})
}

// KeychainOption configures the built-in macOS Keychain provider.
type KeychainOption func(*keychainConfig)

type keychainConfig struct {
	name                       string
	trustApplication           bool
	synchronizable             bool
	accessibleWhenUnlocked     bool
	passwordFunc               PromptFunc
	trustApplicationConfigured bool
}

// KeychainName sets the macOS keychain name.
func KeychainName(name string) KeychainOption {
	return func(cfg *keychainConfig) { cfg.name = name }
}

// KeychainTrustApplication controls whether created items trust the calling
// application by default.
func KeychainTrustApplication(enabled bool) KeychainOption {
	return func(cfg *keychainConfig) {
		cfg.trustApplication = enabled
		cfg.trustApplicationConfigured = true
	}
}

// KeychainSynchronizable controls whether created items can synchronize to
// iCloud.
func KeychainSynchronizable(enabled bool) KeychainOption {
	return func(cfg *keychainConfig) { cfg.synchronizable = enabled }
}

// KeychainAccessibleWhenUnlocked controls whether items are accessible only
// while the device is unlocked.
func KeychainAccessibleWhenUnlocked(enabled bool) KeychainOption {
	return func(cfg *keychainConfig) { cfg.accessibleWhenUnlocked = enabled }
}

// KeychainPrompt sets the macOS keychain password prompt.
func KeychainPrompt(prompt PromptFunc) KeychainOption {
	return func(cfg *keychainConfig) { cfg.passwordFunc = prompt }
}

// KeychainProvider returns the built-in macOS Keychain provider.
func KeychainProvider(opts ...KeychainOption) Provider {
	cfg := keychainConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(KeychainBackend, func(backendCfg *Config) {
		backendCfg.KeychainName = cfg.name
		backendCfg.KeychainSynchronizable = cfg.synchronizable
		backendCfg.KeychainAccessibleWhenUnlocked = cfg.accessibleWhenUnlocked
		if cfg.trustApplicationConfigured {
			backendCfg.KeychainTrustApplication = cfg.trustApplication
		}
		if cfg.passwordFunc != nil {
			backendCfg.KeychainPasswordFunc = cfg.passwordFunc
		}
	})
}

// SecretServiceOption configures the built-in Secret Service provider.
type SecretServiceOption func(*secretServiceConfig)

type secretServiceConfig struct {
	collectionName string
}

// SecretServiceCollection sets the Secret Service collection name.
func SecretServiceCollection(name string) SecretServiceOption {
	return func(cfg *secretServiceConfig) { cfg.collectionName = name }
}

// SecretServiceProvider returns the built-in Secret Service provider.
func SecretServiceProvider(opts ...SecretServiceOption) Provider {
	cfg := secretServiceConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(SecretServiceBackend, func(backendCfg *Config) {
		backendCfg.LibSecretCollectionName = cfg.collectionName
	})
}

// KWalletOption configures the built-in KWallet provider.
type KWalletOption func(*kwalletConfig)

type kwalletConfig struct {
	appID  string
	folder string
}

// KWalletAppID sets the KWallet application id.
func KWalletAppID(appID string) KWalletOption {
	return func(cfg *kwalletConfig) { cfg.appID = appID }
}

// KWalletFolder sets the KWallet folder.
func KWalletFolder(folder string) KWalletOption {
	return func(cfg *kwalletConfig) { cfg.folder = folder }
}

// KWalletProvider returns the built-in KWallet provider.
func KWalletProvider(opts ...KWalletOption) Provider {
	cfg := kwalletConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(KWalletBackend, func(backendCfg *Config) {
		backendCfg.KWalletAppID = cfg.appID
		backendCfg.KWalletFolder = cfg.folder
	})
}

// KeyCtlOption configures the built-in Linux keyctl provider.
type KeyCtlOption func(*keyCtlConfig)

type keyCtlConfig struct {
	scope string
	perm  uint32
}

// KeyCtlScope sets the Linux kernel keyring scope.
func KeyCtlScope(scope string) KeyCtlOption {
	return func(cfg *keyCtlConfig) { cfg.scope = scope }
}

// KeyCtlPerm sets the Linux kernel keyring permission mask.
func KeyCtlPerm(perm uint32) KeyCtlOption {
	return func(cfg *keyCtlConfig) { cfg.perm = perm }
}

// KeyCtlProvider returns the built-in Linux keyctl provider.
func KeyCtlProvider(opts ...KeyCtlOption) Provider {
	cfg := keyCtlConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(KeyCtlBackend, func(backendCfg *Config) {
		backendCfg.KeyCtlScope = cfg.scope
		backendCfg.KeyCtlPerm = cfg.perm
	})
}

// PassOption configures the built-in pass provider.
type PassOption func(*passConfig)

type passConfig struct {
	dir    string
	cmd    string
	prefix string
}

// PassDir sets the password-store directory.
func PassDir(dir string) PassOption {
	return func(cfg *passConfig) { cfg.dir = dir }
}

// PassCmd sets the pass executable name.
func PassCmd(cmd string) PassOption {
	return func(cfg *passConfig) { cfg.cmd = cmd }
}

// PassPrefix sets the item path prefix for pass.
func PassPrefix(prefix string) PassOption {
	return func(cfg *passConfig) { cfg.prefix = prefix }
}

// PassProvider returns the built-in pass provider.
func PassProvider(opts ...PassOption) Provider {
	cfg := passConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(PassBackend, func(backendCfg *Config) {
		backendCfg.PassDir = cfg.dir
		backendCfg.PassCmd = cfg.cmd
		backendCfg.PassPrefix = cfg.prefix
	})
}

// WinCredOption configures the built-in Windows Credential Manager provider.
type WinCredOption func(*winCredConfig)

type winCredConfig struct {
	prefix string
}

// WinCredPrefix sets the key prefix used by Windows Credential Manager.
func WinCredPrefix(prefix string) WinCredOption {
	return func(cfg *winCredConfig) { cfg.prefix = prefix }
}

// WinCredProvider returns the built-in Windows Credential Manager provider.
func WinCredProvider(opts ...WinCredOption) Provider {
	cfg := winCredConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return builtinProvider(WinCredBackend, func(backendCfg *Config) {
		backendCfg.WinCredPrefix = cfg.prefix
	})
}

func builtinProvider(backend Backend, apply func(*Config)) Provider {
	return Provider{
		Backend: backend,
		Open: func(ctx context.Context, opts OpenOptions) (Keyring, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			opener, ok := supportedBackends[backend]
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrUnavailable, backend)
			}

			cfg := Config{
				ServiceName:     opts.ServiceName,
				AllowedBackends: []Backend{backend},
			}
			if apply != nil {
				apply(&cfg)
			}

			ring, err := opener(cfg)
			if err != nil {
				if errors.Is(err, errKeychainSynchronizableWithCustomKeychain) {
					return nil, err
				}
				return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
			}

			return backendAdapter{ring: ring}, nil
		},
	}
}
