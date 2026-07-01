Keyring
=======
[![Maintained fork](https://img.shields.io/badge/maintained%20fork-lox%2Fkeyring-007d9c)](https://github.com/lox/keyring)
[![CI](https://github.com/lox/keyring/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/lox/keyring/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lox/keyring/v2.svg)](https://pkg.go.dev/github.com/lox/keyring/v2)

Keyring provides a context-aware provider API for secure credential storage
services.

## Maintained fork status

This repository is a permanent, maintained fork of [99designs/keyring](https://github.com/99designs/keyring). The upstream project appears to be abandoned; its [maintenance status has been asked about upstream](https://github.com/99designs/keyring/issues/138), but the project remains without active stewardship there.

I originally authored Keyring at 99designs. I'm sad to see the upstream project left unmaintained, so I maintain this fork for ongoing fixes, dependency updates, and platform support. The Go module path for this fork is `github.com/lox/keyring/v2`.

This fork has intentionally diverged from upstream. It uses a different module
path and a context-aware provider API in the root package, so it is not a
drop-in replacement for `github.com/99designs/keyring`.

This is not the only maintained continuation of the project. [ByteNess/keyring](https://github.com/ByteNess/keyring/) is also a maintained fork, with its own feature set and maintenance choices.

The core module includes the encrypted file backend. OS and command-backed
providers can be published as separate modules instead of adding their
dependencies here.

## Code map

The main paths are:

* [keyring.go](keyring.go) - public `Open`, `Keyring`, `Provider`, fallback, and stable errors
* [providers.go](providers.go) - built-in file provider constructor
* [file.go](file.go) - encrypted file backend storage, portable filenames, and legacy filename reads/removes
* [docs/api.md](docs/api.md) - migration notes and provider examples

## Usage

The short version of how to use keyring is shown below.

```go
ctx := context.Background()

ring, _ := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProvider(keyring.FileProvider(
		keyring.FileDir("/path/to/keyring"),
		keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
	)),
)

_ = ring.Set(ctx, keyring.Item{
	Key: "foo",
	Data: []byte("secret-bar"),
})

i, _ := ring.Get(ctx, "foo")

fmt.Printf("%s", i.Data)
```

For more detail on the API please check [the keyring package docs](https://pkg.go.dev/github.com/lox/keyring/v2)

## Provider API

The root package keeps the shared API and file backend in this repository while
desktop and command-backed providers live in their own modules.

```go
ctx := context.Background()

ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProviders(
		keychain.Provider(),
		keyring.FileProvider(
			keyring.FileDir("/path/to/keyring"),
			keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
		),
	),
)
if err != nil {
	log.Fatal(err)
}

_ = ring.Set(ctx, keyring.Item{
	Key:  "foo",
	Data: []byte("secret-bar"),
})
```

External providers can live in separate modules without adding their
dependencies to the core package:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithProviders(
		onepassword.Provider(onepassword.WithVault("Private")),
		keychain.Provider(),
		keyring.FileProvider(
			keyring.FileDir("/path/to/keyring"),
			keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
		),
	),
)
```

See [docs/api.md](docs/api.md) and the package examples for more detail.

## Encrypted file backend

The file backend is built into this repository. Use it for headless, container,
or agent environments where an OS keychain is unavailable or too interactive:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithBackends(keyring.FileBackend),
	keyring.WithProvider(keyring.FileProvider(
		keyring.FileDir("/path/to/keyring"),
		keyring.FilePrompt(keyring.FixedStringPrompt(passphrase)),
	)),
)
```

The backend stores one encrypted file per item under an internal directory in
`FileDir`. Filenames are encoded so application keys containing characters such
as `/`, `:`, `<`, `>`, `?`, or `*` remain portable across platforms. Existing
root-level files written by older versions are still read, listed, and removed
through the legacy filename path.

Applications still own their runtime policy: where the directory lives, how the
passphrase is supplied, whether to force the file backend in headless mode, and
whether to add app-level locking or timeouts. The provider API lets applications
wrap `FileProvider` for those policies without reimplementing encrypted file
storage; [provider_test.go](provider_test.go) includes a small wrapper example.


## Testing

Most tests run with only Go:

```bash
go test ./...
go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

[Vagrant](https://www.vagrantup.com/) can still be used to create linux and windows test environments.

```bash
# Start vagrant
vagrant up

# Run go tests on all platforms
./bin/go-test
```


## Contributing

Contributions to this fork of the keyring package are most welcome from engineers of all backgrounds and skill levels. In particular the addition of extra backends across popular operating systems would be appreciated.

To make a contribution:

  * Fork this repository
  * Make your changes on the fork
  * Submit a pull request back to this repo with a clear description of the problem you're solving
  * Ensure your PR passes all current (and new) tests

...and we'll do our best to get your work merged in
