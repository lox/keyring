# API

The root `github.com/lox/keyring` package keeps keyring's stable desktop
backends in this repository, but moves backend selection to explicit provider
values. Heavy or vendor-specific backends such as 1Password can live in separate
modules while still participating in the same `Open` call.

## Opening A Keyring

```go
ctx := context.Background()

ring, err := keyring.Open(ctx,
	keyring.WithServiceName("gog"),
	keyring.WithBackends(keyring.KeychainBackend, keyring.FileBackend),
	keyring.WithProvider(keyring.FileProvider(
		keyring.FileDir("/path/to/keyring"),
		keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
	)),
)
if err != nil {
	return err
}
```

If `WithBackends` is not provided, `Open` tries the built-in providers that are
available on the current platform in the package's default order. Additional
providers can be added with `WithProvider` or `WithProviders`.

## Migrating From Config

Old callers opened keyrings with `keyring.Open(keyring.Config{...})`. New
callers pass `context.Context` plus options:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("aws-vault"),
	keyring.WithBackends(keyring.KeychainBackend, keyring.FileBackend),
	keyring.WithProvider(keyring.KeychainProvider(
		keyring.KeychainName("aws-vault"),
		keyring.KeychainTrustApplication(true),
	)),
	keyring.WithProvider(keyring.FileProvider(
		keyring.FileDir("~/.awsvault/keys/"),
		keyring.FilePrompt(fileKeyringPassphrasePrompt),
	)),
)
```

The mechanical mapping is:

- `Config.ServiceName` -> `WithServiceName`
- `Config.AllowedBackends` -> `WithBackends`
- backend-specific `Config` fields -> the matching built-in provider options
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

Some built-in providers own OS resources. When an opened keyring also implements
`io.Closer`, callers should close it when they are done.

Metadata is optional because not every backend can provide it without prompting
or exposing implementation details:

```go
type MetadataReader interface {
	Metadata(context.Context, string) (Metadata, error)
}
```

## Providers

Providers are ordinary values:

```go
type Provider struct {
	Backend keyring.Backend
	Open    func(context.Context, keyring.OpenOptions) (keyring.Keyring, error)
}
```

A provider with the same backend name as a built-in backend replaces that
built-in provider for the current `Open` call. That lets applications wrap or
specialize built-in behavior without changing the core library.

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
	keyring.WithBackends(onepassword.Backend, keyring.KeychainBackend, keyring.FileBackend),
	keyring.WithProvider(onepassword.Provider(
		onepassword.WithVault("Private"),
		onepassword.WithAccount("example.1password.com"),
	)),
)
```

The core package does not need to know that `onepassword.Backend` exists. It only
needs a provider value that implements the shared contract.

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
