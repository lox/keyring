Keyring
=======
[![Maintained fork](https://img.shields.io/badge/maintained%20fork-lox%2Fkeyring-007d9c)](https://github.com/lox/keyring)
[![CI](https://github.com/lox/keyring/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/lox/keyring/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/99designs/keyring.svg)](https://pkg.go.dev/github.com/99designs/keyring)

Keyring provides a common interface to a range of secure credential storage services.

## Maintained fork status

This repository is a permanent, maintained fork of [99designs/keyring](https://github.com/99designs/keyring). The upstream project appears to be abandoned; its [maintenance status has been asked about upstream](https://github.com/99designs/keyring/issues/138), but the project remains without active stewardship there.

I originally authored Keyring at 99designs. I'm sad to see the upstream project left unmaintained, so I maintain this fork for ongoing fixes, dependency updates, and platform support. The Go module path intentionally remains `github.com/99designs/keyring` for compatibility with existing users.

This is not the only maintained continuation of the project. [ByteNess/keyring](https://github.com/ByteNess/keyring/) is also a maintained fork, with its own feature set and maintenance choices.

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

For more detail on the API please check [the keyring package docs](https://pkg.go.dev/github.com/99designs/keyring)


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

Contributions to this fork of the keyring package are most welcome from engineers of all backgrounds and skill levels. In particular the addition of extra backends across popular operating systems would be appreciated.

To make a contribution:

  * Fork this repository
  * Make your changes on the fork
  * Submit a pull request back to this repo with a clear description of the problem you're solving
  * Ensure your PR passes all current (and new) tests

...and we'll do our best to get your work merged in
