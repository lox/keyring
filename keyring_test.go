package keyring_test

import (
	"context"
	"log"

	"github.com/lox/keyring/v2"
)

func ExampleOpen() {
	ctx := context.Background()

	kr, err := keyring.Open(ctx,
		keyring.WithServiceName("my-service"),
		keyring.WithProvider(keyring.FileProvider(
			keyring.FileDir("/path/to/keyring"),
			keyring.FilePrompt(keyring.FixedStringPrompt("passphrase")),
		)),
	)
	if err != nil {
		log.Fatal(err)
	}

	v, err := kr.Get(ctx, "llamas")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("llamas was %v", v)
}
