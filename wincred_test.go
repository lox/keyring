//go:build windows
// +build windows

package keyring_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/lox/keyring"
)

func openWinCred(ctx context.Context) (keyring.Keyring, error) {
	return keyring.Open(ctx,
		keyring.WithBackends(keyring.WinCredBackend),
		keyring.WithProvider(keyring.WinCredProvider()),
	)
}

func TestSavingCredentialsWithWinCred(t *testing.T) {
	ctx := context.Background()
	kr, err := openWinCred(ctx)
	if err != nil {
		t.Fatal(err)
	}

	item1 := keyring.Item{
		Key:  "test",
		Data: []byte("loose lips sink ships"),
	}

	err = kr.Set(ctx, item1)
	if err != nil {
		t.Fatal(err)
	}

	item2, err := kr.Get(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(item1, item2) {
		t.Fatalf("Expected %#v, got %#v", item1, item2)
	}

	err = kr.Remove(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = kr.Get(ctx, "test")
	if err != keyring.ErrKeyNotFound {
		t.Fatalf("Expected %v, got %v", keyring.ErrKeyNotFound, err)
	}
}

func TestListingCredentialsWithWinCred(t *testing.T) {
	ctx := context.Background()
	kr, err := openWinCred(ctx)
	if err != nil {
		t.Fatal(err)
	}

	item1 := keyring.Item{
		Key:  "test",
		Data: []byte("loose lips sink ships"),
	}

	err = kr.Set(ctx, item1)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := kr.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if expected := []string{"test"}; !reflect.DeepEqual(keys, expected) {
		t.Fatalf("Unexpected keys, got %#v, expected %#v", keys, expected)
	}

	err = kr.Remove(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
}

func TestWinCredGetWhenEmpty(t *testing.T) {
	ctx := context.Background()
	kr, err := openWinCred(ctx)
	if err != nil {
		t.Fatal(err)
	}

	_, err = kr.Get(ctx, "llamas")
	if err != keyring.ErrKeyNotFound {
		t.Fatal("Expected ErrKeyNotFound")
	}
}

func TestWinCredRemoveWhenEmpty(t *testing.T) {
	ctx := context.Background()
	kr, err := openWinCred(ctx)
	if err != nil {
		t.Fatal(err)
	}

	err = kr.Remove(ctx, "no-such-key")
	if err != keyring.ErrKeyNotFound {
		t.Fatal("Expected ErrKeyNotFound")
	}
}

func TestWinCredKeysWhenEmpty(t *testing.T) {
	ctx := context.Background()
	kr, err := openWinCred(ctx)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := kr.Keys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}
