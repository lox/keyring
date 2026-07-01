// Command keyring provides a small manual testing CLI for the keyring package.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lox/keyring/v2"
)

func main() {
	ctx := context.Background()
	serviceName := flag.String("service", "example", "The keyring service to use")
	keyName := flag.String("key", "example", "The key to use")
	backend := flag.String("backend", "", "A specific backend to use")
	fileDir := flag.String("file-dir", "", "Directory to use with the file backend")
	debug := flag.Bool("debug", false, "Whether to enable debugging in keyring")
	listBackends := flag.Bool("list-backends", false, "Whether to list backends")

	// actions to take
	actionListKeys := flag.Bool("list-keys", false, "Whether to list keys")
	actionSetValue := flag.String("set", "", "The value to set")

	flag.Parse()

	// Handle -list-backends
	if *listBackends {
		fmt.Printf("%s\n", keyring.FileBackend)
		os.Exit(0)
	}

	// Log to stderr
	log.SetOutput(os.Stderr)

	keyring.Debug = *debug

	var allowedBackends []keyring.Backend
	if *backend != "" {
		if keyring.Backend(*backend) != keyring.FileBackend {
			log.Fatalf("Backend %q isn't built into this CLI. Use -list-backends to see what is.", *backend)
		}
		allowedBackends = append(allowedBackends, keyring.Backend(*backend))
	} else {
		allowedBackends = []keyring.Backend{keyring.FileBackend}
	}

	if *fileDir == "" {
		log.Fatal("-file-dir is required")
	}
	opts := []keyring.Option{
		keyring.WithServiceName(*serviceName),
		keyring.WithBackends(allowedBackends...),
		keyring.WithProvider(keyring.FileProvider(
			keyring.FileDir(*fileDir),
			keyring.FilePrompt(keyring.TerminalPrompt),
		)),
	}

	ring, err := keyring.Open(ctx, opts...)
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case *actionListKeys:
		if *debug {
			log.Printf("Listing keys in service %q in backend %q",
				*serviceName, allowedBackends[0])
		}
		keys, err := ring.Keys(ctx)
		if err != nil {
			log.Fatalf("Failed to list keys: %#v", err)
		}
		for _, key := range keys {
			fmt.Printf("%s\n", key)
		}

	case *actionSetValue != "":
		if *debug {
			log.Printf("Setting key %q in service %q in backend %q",
				*keyName, *serviceName, allowedBackends[0])
		}
		err := ring.Set(ctx, keyring.Item{
			Key:  *keyName,
			Data: []byte(*actionSetValue),
		})
		if err != nil {
			log.Fatal(err)
		}

	default:
		if *debug {
			log.Printf("Getting key %q in service %q in backend %q",
				*keyName, *serviceName, allowedBackends[0])
		}

		i, err := ring.Get(ctx, *keyName)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s", i.Data)
	}
}
