package keyring_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	keyring "github.com/lox/keyring/v2"
)

func ExampleOpen() {
	ctx := context.Background()

	ring, err := keyring.Open(ctx,
		keyring.WithServiceName("example"),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := ring.Set(ctx, keyring.Item{
		Key:  "foo",
		Data: []byte("secret-bar"),
	}); err != nil {
		log.Fatal(err)
	}

	item, err := ring.Get(ctx, "foo")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", item.Data)
}

func ExampleOpen_fileProvider() {
	ctx := context.Background()

	ring, err := keyring.Open(ctx,
		keyring.WithServiceName("example"),
		keyring.WithBackends(keyring.FileBackend),
		keyring.WithProvider(keyring.FileProvider(
			keyring.FileDir("/path/to/keyring"),
			keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = ring
}

func ExampleOpen_externalProvider() {
	ctx := context.Background()

	const onePasswordBackend keyring.Backend = "1password"
	onePasswordProvider := keyring.Provider{
		Backend: onePasswordBackend,
		Open: func(context.Context, keyring.OpenOptions) (keyring.Keyring, error) {
			return nil, errors.New("open 1password provider")
		},
	}

	_, _ = keyring.Open(ctx,
		keyring.WithServiceName("example"),
		keyring.WithBackends(onePasswordBackend, keyring.KeychainBackend, keyring.FileBackend),
		keyring.WithProvider(onePasswordProvider),
	)
}
