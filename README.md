Keyring
=======
[![CI](https://github.com/lox/keyring/actions/workflows/test.yml/badge.svg)](https://github.com/lox/keyring/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lox/keyring.svg)](https://pkg.go.dev/github.com/lox/keyring)

Keyring provides a common interface to a range of secure credential storage services. Originally developed as part of [AWS Vault](https://github.com/99designs/aws-vault), a command line tool for securely managing AWS access from developer workstations.

Currently Keyring supports the following backends
 * [macOS Keychain](https://support.apple.com/en-au/guide/keychain-access/welcome/mac)
 * [Windows Credential Manager](https://support.microsoft.com/en-au/help/4026814/windows-accessing-credential-manager)
 * Secret Service ([Gnome Keyring](https://wiki.gnome.org/Projects/GnomeKeyring), [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5))
 * [KWallet](https://kde.org/applications/system/org.kde.kwalletmanager5)
 * [Pass](https://www.passwordstore.org/)
 * [Encrypted file (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
 * [KeyCtl](https://linux.die.net/man/1/keyctl)


## Usage

The short version of how to use keyring is shown below.

```go
ring, _ := keyring.Open(keyring.Config{
  ServiceName: "example",
})

_ = ring.Set(keyring.Item{
	Key: "foo",
	Data: []byte("secret-bar"),
})

i, _ := ring.Get("foo")

fmt.Printf("%s", i.Data)
```

For more detail on the API please check [the keyring package docs](https://pkg.go.dev/github.com/lox/keyring)

## v2 API

The `v2` package contains the next API shape. It keeps the built-in desktop
backends in this repository while making backend selection extensible through
explicit provider values and OptionFunc configuration.

Import it as `github.com/lox/keyring/v2`.

```go
ctx := context.Background()

ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithBackends(keyring.KeychainBackend, keyring.FileBackend),
	keyring.WithProvider(keyring.FileProvider(
		keyring.FileDir("/path/to/keyring"),
		keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
	)),
)
if err != nil {
	log.Fatal(err)
}

_ = ring.Set(ctx, keyring.Item{
	Key:  "foo",
	Data: []byte("secret-bar"),
})
```

External providers, such as a future 1Password provider, can live in separate
modules without adding their dependencies to the core package:

```go
ring, err := keyring.Open(ctx,
	keyring.WithServiceName("example"),
	keyring.WithBackends(onepassword.Backend, keyring.KeychainBackend, keyring.FileBackend),
	keyring.WithProvider(onepassword.Provider(
		onepassword.WithVault("Private"),
	)),
)
```

See [docs/v2-api.md](docs/v2-api.md) and the examples in the `v2` package for
more detail.


## Testing

Most tests run with only Go:

```bash
go test ./...
go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

The `pass` integration tests require `pass` and `gpg`; they are skipped when those tools are not installed. Secret Service tests require an interactive DBus-backed desktop session and are skipped in GitHub Actions.

[Vagrant](https://www.vagrantup.com/) can still be used to create linux and windows test environments.

```bash
# Start vagrant
vagrant up

# Run go tests on all platforms
./bin/go-test
```


## Contributing

Contributions to the keyring package are most welcome from engineers of all backgrounds and skill levels. In particular the addition of extra backends across popular operating systems would be appreciated.

This project will adhere to the [Go Community Code of Conduct](https://golang.org/conduct) in the github provided discussion spaces, with the moderators being the 99designs engineering team.

To make a contribution:

  * Fork the repository
  * Make your changes on the fork
  * Submit a pull request back to this repo with a clear description of the problem you're solving
  * Ensure your PR passes all current (and new) tests
  * Ideally verify that [aws-vault](https://github.com/99designs/aws-vault) works with your changes (optional)

...and we'll do our best to get your work merged in
