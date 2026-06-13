package keyring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyringSetWhenEmpty(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}
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

func TestFileKeyringGetWithSlashes(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	item := Item{Key: "https://aws-sso-portal.awsapps.com/start", Data: []byte("https://aws-sso-portal.awsapps.com/start")}

	if err := k.Set(item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(item.Key); err != nil {
		t.Fatal(err)
	}
}

func TestFileKeyringRemoveWhenEmpty(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	err := k.Remove("no-such-key")
	if err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestFileKeyringRejectsFileDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring")
	if err := os.WriteFile(path, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}

	k := &fileKeyring{
		dir:          path,
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	if _, err := k.Keys(); err == nil {
		t.Fatal("expected file keyring to reject a file path")
	}
}

func TestFilenameWithBadChars(t *testing.T) {
	a := `abc/.././123`
	e := filenameEscape(a)
	if e != `abc%2F..%2F.%2F123` {
		t.Fatalf("Unexpected result from filenameEscape: %s", e)
	}

	b := filenameUnescape(e)
	if b != a {
		t.Fatal("Unexpected filenameEscape")
	}
}
