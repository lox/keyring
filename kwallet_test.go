//go:build linux
// +build linux

package keyring

import (
	"context"
	"errors"
	"testing"
)

func TestKWalletOpenFallsBackWhenDBusIsUnavailable(t *testing.T) {
	dbusErr := errors.New("dbus unavailable")
	originalNewKwalletBinding := newKwalletBinding
	newKwalletBinding = func() (*kwalletBinding, error) {
		return nil, dbusErr
	}
	t.Cleanup(func() {
		newKwalletBinding = originalNewKwalletBinding
	})

	ring, err := Open(context.Background(),
		WithBackends(KWalletBackend, FileBackend),
		WithProvider(FileProvider(
			FileDir(t.TempDir()),
			FilePrompt(FixedStringPrompt("test password")),
		)),
	)
	if err != nil {
		t.Fatalf("expected file fallback after KWallet opener failure, got %v", err)
	}
	adapter, ok := ring.(backendAdapter)
	if !ok {
		t.Fatalf("expected backendAdapter, got %T", ring)
	}
	if _, ok := adapter.ring.(*fileKeyring); !ok {
		t.Fatalf("expected *fileKeyring fallback, got %T", adapter.ring)
	}
}

func TestKWalletCloseClosesDBusConnection(t *testing.T) {
	closed := false
	ring := &kwalletKeyring{
		wallet: kwalletBinding{
			closeFunc: func() error {
				closed = true
				return nil
			},
		},
	}

	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("expected close to close DBus connection")
	}
}
