//go:build !windows
// +build !windows

package keyring

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func runCmd(t *testing.T, cmds ...string) {
	t.Helper()
	cmd := exec.Command(cmds[0], cmds[1:]...) //nolint:noctx // Test helper runs short-lived setup commands.
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(cmd)
		fmt.Println(string(out))
		t.Fatal(err)
	}
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s executable not found: %v", name, err)
	}
}

func unsetenv(t *testing.T, key string) {
	t.Helper()

	value, ok := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(key, value)
			return
		}
		_ = os.Unsetenv(key)
	})
}

func setup(t *testing.T) (*passKeyring, func(t *testing.T)) {
	t.Helper()
	requireCommand(t, "pass")
	requireCommand(t, "gpg")

	pwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// the default temp directory can't be used because gpg-agent complains with "socket name too long"
	tmpdir, err := os.MkdirTemp("/tmp", "keyring-pass-test-*")
	if err != nil {
		t.Fatal(err)
	}

	// Initialise a blank GPG homedir; import & trust the test key
	gnupghome := filepath.Join(tmpdir, ".gnupg")
	err = os.Mkdir(gnupghome, os.FileMode(int(0700)))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", gnupghome)
	unsetenv(t, "GPG_AGENT_INFO")
	unsetenv(t, "GPG_TTY")
	runCmd(t, "gpg", "--import", filepath.Join(pwd, "testdata", "test-gpg.key"))
	runCmd(t, "gpg", "--import-ownertrust", filepath.Join(pwd, "testdata", "test-ownertrust-gpg.txt"))

	passdir := filepath.Join(tmpdir, ".password-store")
	k := &passKeyring{
		dir:     passdir,
		passcmd: "pass",
		prefix:  "keyring",
	}

	cmd := k.pass("init", "test@example.com")
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatal(err)
	}

	return k, func(t *testing.T) {
		t.Helper()
		if err := os.RemoveAll(tmpdir); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPassKeyringSetWhenEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := k.Get("llamas")
	if err != nil {
		t.Fatal(err)
	}

	if string(foundItem.Data) != "llamas are great" {
		t.Fatalf("Value stored was not the value retrieved: %q", foundItem.Data)
	}

	if foundItem.Key != "llamas" {
		t.Fatalf("Key wasn't persisted: %q", foundItem.Key)
	}
}

func TestPassKeyringKeysWhenEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestPassKeyringKeysWhenNotEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	items := []Item{
		{Key: "llamas", Data: []byte("llamas are great")},
		{Key: "alpacas", Data: []byte("alpacas are better")},
		{Key: "africa/elephants", Data: []byte("who doesn't like elephants")},
	}

	for _, item := range items {
		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != len(items) {
		t.Fatalf("Expected %d keys, got %d", len(items), len(keys))
	}

	expectedKeys := []string{
		"africa/elephants",
		"alpacas",
		"llamas",
	}

	if !reflect.DeepEqual(keys, expectedKeys) {
		t.Fatalf("Expected keys %v, got %v", expectedKeys, keys)
	}
}

func TestPassKeyringRemoveWhenEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	err := k.Remove("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestPassKeyringRemoveWhenNotEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(item.Key); err != nil {
		t.Fatal(err)
	}

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys, got %d", len(keys))
	}
}

func TestPassKeyringGetWhenEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	_, err := k.Get("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestPassKeyringGetWhenNotEmpty(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	v1, err := k.Get(item.Key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v1.Data, item.Data) {
		t.Fatal("Expected item not returned")
	}
}

func TestPassKeyringKeysWithSymlink(t *testing.T) {
	k, teardown := setup(t)
	defer teardown(t)

	items := []Item{
		{Key: "llamas", Data: []byte("llamas are great")},
		{Key: "alpacas", Data: []byte("alpacas are better")},
		{Key: "africa/elephants", Data: []byte("who doesn't like elephants")},
	}

	for _, item := range items {
		if err := k.Set(item); err != nil {
			t.Fatal(err)
		}
	}

	s := filepath.Join(t.TempDir(), "newsymlink")
	err := os.Symlink(k.dir, s)
	if err != nil {
		t.Fatal(err)
	}
	k.dir = s

	keys, err := k.Keys()
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != len(items) {
		t.Fatalf("Expected %d keys, got %d", len(items), len(keys))
	}

	expectedKeys := []string{
		"africa/elephants",
		"alpacas",
		"llamas",
	}

	if !reflect.DeepEqual(keys, expectedKeys) {
		t.Fatalf("Expected keys %v, got %v", expectedKeys, keys)
	}
}
