package keyring

import (
	"context"

	v1 "github.com/lox/keyring"
)

// PromptFunc prompts for a password or passphrase.
type PromptFunc func(string) (string, error)

// FixedStringPrompt returns a prompt that always returns password.
func FixedStringPrompt(password string) PromptFunc {
	return func(string) (string, error) { return password, nil }
}

// TerminalPrompt prompts for a passphrase on the terminal.
var TerminalPrompt PromptFunc = PromptFunc(v1.TerminalPrompt)

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
	return v1Provider(FileBackend, func(v1cfg *v1.Config) {
		v1cfg.FileDir = cfg.dir
		if cfg.prompt != nil {
			v1cfg.FilePasswordFunc = v1.PromptFunc(cfg.prompt)
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
	return v1Provider(KeychainBackend, func(v1cfg *v1.Config) {
		v1cfg.KeychainName = cfg.name
		v1cfg.KeychainSynchronizable = cfg.synchronizable
		v1cfg.KeychainAccessibleWhenUnlocked = cfg.accessibleWhenUnlocked
		if cfg.trustApplicationConfigured {
			v1cfg.KeychainTrustApplication = cfg.trustApplication
		}
		if cfg.passwordFunc != nil {
			v1cfg.KeychainPasswordFunc = v1.PromptFunc(cfg.passwordFunc)
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
	return v1Provider(SecretServiceBackend, func(v1cfg *v1.Config) {
		v1cfg.LibSecretCollectionName = cfg.collectionName
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
	return v1Provider(KWalletBackend, func(v1cfg *v1.Config) {
		v1cfg.KWalletAppID = cfg.appID
		v1cfg.KWalletFolder = cfg.folder
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
	return v1Provider(KeyCtlBackend, func(v1cfg *v1.Config) {
		v1cfg.KeyCtlScope = cfg.scope
		v1cfg.KeyCtlPerm = cfg.perm
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
	return v1Provider(PassBackend, func(v1cfg *v1.Config) {
		v1cfg.PassDir = cfg.dir
		v1cfg.PassCmd = cfg.cmd
		v1cfg.PassPrefix = cfg.prefix
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
	return v1Provider(WinCredBackend, func(v1cfg *v1.Config) {
		v1cfg.WinCredPrefix = cfg.prefix
	})
}

func v1Provider(backend Backend, apply func(*v1.Config)) Provider {
	return Provider{
		Backend: backend,
		Open: func(ctx context.Context, opts OpenOptions) (Keyring, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			cfg := v1.Config{
				ServiceName:     opts.ServiceName,
				AllowedBackends: []v1.BackendType{v1Backend(backend)},
			}
			if apply != nil {
				apply(&cfg)
			}

			ring, err := v1.Open(cfg)
			if err != nil {
				return nil, mapError(err)
			}

			return v1Keyring{ring: ring}, nil
		},
	}
}

func v1Backend(backend Backend) v1.BackendType {
	return v1.BackendType(backend)
}
