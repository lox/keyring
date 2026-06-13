//go:build linux
// +build linux

package keyring

import (
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

	ring, err := Open(Config{
		AllowedBackends:  []BackendType{KWalletBackend, FileBackend},
		FileDir:          t.TempDir(),
		FilePasswordFunc: FixedStringPrompt("test password"),
	})
	if err != nil {
		t.Fatalf("expected file fallback after KWallet opener failure, got %v", err)
	}
	if _, ok := ring.(*fileKeyring); !ok {
		t.Fatalf("expected *fileKeyring fallback, got %T", ring)
	}
}
