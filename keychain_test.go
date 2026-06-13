//go:build darwin
// +build darwin

package keyring

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOSXKeychainKeyringSet(t *testing.T) {
	k := newTestKeychain(t)

	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v.Data, item.Data)
	}

	if v.Key != item.Key {
		t.Fatalf("Key stored was not the data retrieved: %q vs %q", v.Key, item.Key)
	}

	if v.Description != item.Description {
		t.Fatalf("Description stored was not the data retrieved: %q vs %q", v.Description, item.Description)
	}
}

func TestOSXKeychainKeyringOverwrite(t *testing.T) {
	k := newTestKeychain(t)

	item1 := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item1); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v1.Data) != string(item1.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item1.Data)
	}

	item2 := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are great"),
	}

	if err := k.Set(item2); err != nil {
		t.Fatal(err)
	}

	v2, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(v2.Data) != string(item2.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v2.Data, item2.Data)
	}
}

func TestOSXKeychainKeyringListKeysWhenEmpty(t *testing.T) {
	k := newTestKeychain(t)

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestOSXKeychainKeyringListKeysWhenNotEmpty(t *testing.T) {
	k := newTestKeychain(t)

	keys := []string{"key1", "key2", "key3"}

	for _, key := range keys {
		item := Item{
			Key:  key,
			Data: []byte("llamas are great"),
		}

		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	keys2, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(keys, keys2) {
		t.Fatalf("Retrieved keys weren't the same: %q vs %q", keys, keys2)
	}
}

func TestOSXKeychainConfigMapsOptions(t *testing.T) {
	keychainName := tempKeychainName(t)

	ring, err := Open(Config{
		AllowedBackends:                []BackendType{KeychainBackend},
		ServiceName:                    "test",
		KeychainName:                   keychainName,
		KeychainPasswordFunc:           FixedStringPrompt("test password"),
		KeychainTrustApplication:       true,
		KeychainSynchronizable:         true,
		KeychainAccessibleWhenUnlocked: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	k, ok := ring.(*keychain)
	if !ok {
		t.Fatalf("expected *keychain, got %T", ring)
	}
	if k.path != keychainName+".keychain" {
		t.Fatalf("expected keychain path %q, got %q", keychainName+".keychain", k.path)
	}
	if !k.isTrusted {
		t.Fatal("expected keychain to trust the application")
	}
	if !k.isSynchronizable {
		t.Fatal("expected keychain to be synchronizable")
	}
	if !k.isAccessibleWhenUnlocked {
		t.Fatal("expected keychain to be accessible when unlocked")
	}
}

func TestOSXKeychainGetMetadataUsesConfiguredKeychain(t *testing.T) {
	ring := newTestKeyring(t, "test-metadata")
	item := Item{
		Key:         "llamas",
		Label:       "Metadata label",
		Description: "Metadata description",
		Data:        []byte("llamas are ok"),
	}

	if err := ring.Set(item); err != nil {
		t.Fatal(err)
	}

	metadata, err := ring.GetMetadata(item.Key)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Item == nil {
		t.Fatal("expected item metadata")
	}
	if metadata.Key != item.Key {
		t.Fatalf("Key stored was not the metadata retrieved: %q vs %q", metadata.Key, item.Key)
	}
	if metadata.Label != item.Label {
		t.Fatalf("Label stored was not the metadata retrieved: %q vs %q", metadata.Label, item.Label)
	}
	if metadata.Description != item.Description {
		t.Fatalf("Description stored was not the metadata retrieved: %q vs %q", metadata.Description, item.Description)
	}
	if len(metadata.Data) != 0 {
		t.Fatalf("Expected metadata data to be empty, got %q", metadata.Data)
	}
	if metadata.ModificationTime.IsZero() {
		t.Fatal("Expected metadata modification time to be set")
	}
}

func newTestKeychain(t *testing.T) *keychain {
	t.Helper()

	return &keychain{
		path:         tempKeychainName(t) + ".keychain",
		passwordFunc: FixedStringPrompt("test password"),
		service:      "test",
		isTrusted:    true,
	}
}

func newTestKeyring(t *testing.T, service string) Keyring {
	t.Helper()

	ring, err := Open(Config{
		AllowedBackends:          []BackendType{KeychainBackend},
		ServiceName:              service,
		KeychainName:             tempKeychainName(t),
		KeychainPasswordFunc:     FixedStringPrompt("test password"),
		KeychainTrustApplication: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	return ring
}

func tempKeychainName(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "keyring-test")
	t.Cleanup(func() {
		deleteKeychain(t, path+".keychain")
	})

	return path
}

func deleteKeychain(t *testing.T, path string) {
	t.Helper()

	for _, path := range []string{path, path + "-db"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove keychain %q: %v", path, err)
		}
	}
}

func TestOSXKeychainGetKeyWhenEmpty(t *testing.T) {
	k := newTestKeychain(t)

	_, err := k.Get("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatal("expected ErrKeyNotFound")
	}
}

func TestOSXKeychainGetKeyWhenNotEmpty(t *testing.T) {
	k := newTestKeychain(t)
	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}
	if string(v1.Data) != string(item.Data) {
		t.Fatalf("Data stored was not the data retrieved: %q vs %q", v1.Data, item.Data)
	}
}

func TestOSXKeychainRemoveKeyWhenEmpty(t *testing.T) {
	k := newTestKeychain(t)

	err := k.Remove("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestOSXKeychainRemoveKeyWhenNotEmpty(t *testing.T) {
	k := newTestKeychain(t)
	item := Item{
		Key:         "llamas",
		Label:       "Arbitrary label",
		Description: "A freetext description",
		Data:        []byte("llamas are ok"),
	}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	_, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	err = k.Remove("llamas")
	if err != nil {
		t.Fatal(err)
	}
}
