# API

The root `github.com/lox/keyring/v2` package keeps keyring's shared API and
encrypted file backend in this repository. Desktop, command-backed, and vendor
providers can live in separate modules while still participating in the same
`Open` call.

## Opening A Keyring

```go
ctx := context.Background()

ring, err := keyring.Open(ctx,
	keyring.WithServiceName("gog"),
	keyring.WithProviders(
		keychain.Provider(),
		keyring.FileProvider(
			keyring.FileDir("/path/to/keyring"),
			keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
		),
	),
)
if err != nil {
	return err
}
```

If `WithBackends` is not provided, `Open` tries providers in the order they were
passed to `WithProvider` or `WithProviders`.

## Migrating From Config

The old `keyring.Config` entry point has been removed. New callers pass
`context.Context` plus options:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("aws-vault"),
	keyring.WithProviders(
		keychain.Provider(
			keychain.Name("aws-vault"),
			keychain.TrustApplication(true),
		),
		keyring.FileProvider(
			keyring.FileDir("~/.awsvault/keys/"),
			keyring.FilePrompt(fileKeyringPassphrasePrompt),
		),
	),
)
```

The mechanical mapping is:

- `Config.ServiceName` -> `WithServiceName`
- `Config.AllowedBackends` -> `WithBackends`
- backend-specific `Config` fields -> the matching provider module options
- `ring.Get(key)` / `ring.Set(item)` / `ring.Keys()` -> pass `ctx` as the first argument
- `ring.GetMetadata(key)` -> use `MetadataReader` when the opened keyring supports it

## Interfaces

The core interface is context-aware and intentionally small:

```go
type Keyring interface {
	Get(context.Context, string) (Item, error)
	Set(context.Context, Item) error
	Remove(context.Context, string) error
	Keys(context.Context) ([]string, error)
}
```

Some provider modules own OS resources. When an opened keyring also implements
`io.Closer`, callers should close it when they are done.

Metadata is optional because not every backend can provide it without prompting
or exposing implementation details:

```go
type MetadataReader interface {
	Metadata(context.Context, string) (Metadata, error)
}
```

## Operation Timeouts

Callers that need a hard per-operation deadline can wrap an opened keyring:

```go
ring = keyring.Timeout(ring, 10*time.Second)
```

The wrapper passes a cancellable context to the provider and returns an error
wrapping `context.DeadlineExceeded` when the timeout wins. If a provider ignores
context cancellation, its worker goroutine may stay blocked until that provider
returns.

## Providers

Providers are ordinary values:

```go
type Provider struct {
	Backend keyring.Backend
	Open    func(context.Context, keyring.OpenOptions) (keyring.Keyring, error)
}
```

A provider with the same backend name as an earlier provider replaces it for the
current `Open` call. Provider order is fallback order.

## File Backend

The encrypted file backend is a built-in provider:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("gog"),
	keyring.WithBackends(keyring.FileBackend),
	keyring.WithProvider(keyring.FileProvider(
		keyring.FileDir(keyringDir),
		keyring.FilePrompt(keyring.FixedStringPrompt(passphrase)),
	)),
)
```

`file.go` owns the encrypted file storage. It writes one encrypted file per item
under an internal directory, encodes filenames so application keys are portable
across platforms, and continues to read, list, and remove older root-level files
written with the previous filename format.

Applications own the policy around that storage: environment variables,
interactive prompting, headless detection, service-specific key naming, locking,
and operation timeouts. If an application needs those policies, wrap the built-in
provider for the current `Open` call instead of copying the file backend.

For example, an application can add locking, timeouts, metrics, or migration
logic around the built-in file backend:

```go
rawFile := keyring.FileProvider(
	keyring.FileDir(dir),
	keyring.FilePrompt(prompt),
)

appFile := keyring.Provider{
	Backend: keyring.FileBackend,
	Open: func(ctx context.Context, opts keyring.OpenOptions) (keyring.Keyring, error) {
		ring, err := rawFile.Open(ctx, opts)
		if err != nil {
			return nil, err
		}
		return withFilePolicy(ring), nil
	},
}
```

## External Providers

Vendor-specific providers should keep their own dependencies and configuration
outside the core module:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("gog"),
	keyring.WithProviders(
		onepassword.Provider(
			onepassword.WithVault("Private"),
			onepassword.WithAccount("example.1password.com"),
		),
		keychain.Provider(),
		keyring.FileProvider(
			keyring.FileDir(keyringDir),
			keyring.FilePrompt(prompt),
		),
	),
)
```

The core package does not need to know that `onepassword.Backend` exists. It only
needs a provider value that implements the shared contract.

### macOS Keychain Touch ID

The `github.com/lox/keyring-keychain` provider supports Touch ID without making
CLI applications look like signed macOS app bundles:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("gog"),
	keyring.WithProvider(keychain.Provider(
		keychain.TouchID(keychain.TouchIDConfig{
			Reason: "access gog credentials",
		}),
	)),
)
```

`TouchID` encrypts item data to a per-item Secure Enclave-backed key and stores
the encrypted envelope as a normal keychain item. Reading that item back prompts
for Touch ID, or the account password under the default user-presence policy.

Touch ID-protected items are device-bound and cannot be combined with
`keychain.Synchronizable(true)`. Items written before enabling `TouchID` remain
readable without a prompt until the application rewrites them.

## Fallback

By default, `Open` tries the next backend only when a provider returns
`ErrUnavailable`. Other errors, such as access denied or invalid configuration,
stop the open attempt and are returned to the caller.

Callers that want the previous "try the next backend after any open error"
behavior can opt in:

```go
ring, err := keyring.Open(ctx,
	keyring.WithFallbackPolicy(keyring.FallbackOnError),
)
```

## Error Semantics

The package exposes stable errors for common caller decisions:

- `ErrUnavailable`
- `ErrNotFound`
- `ErrAccessDenied`
- `ErrTooLarge`
- `ErrMetadataUnsupported`
- `ErrMetadataNeedsUnlock`

Backends may wrap lower-level errors, but callers should use `errors.Is` against
the stable errors above.
