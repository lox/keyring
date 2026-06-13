package keyring_test

import (
	"context"
	"log"

	"github.com/lox/keyring"
)

func ExampleOpen() {
	ctx := context.Background()

	// Use the best keyring implementation for your operating system
	kr, err := keyring.Open(ctx, keyring.WithServiceName("my-service"))
	if err != nil {
		log.Fatal(err)
	}

	v, err := kr.Get(ctx, "llamas")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("llamas was %v", v)
}
