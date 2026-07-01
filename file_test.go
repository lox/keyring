package keyring

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jose "github.com/dvsekhvalnov/jose2go"
)

func TestFileKeyringSetWhenEmpty(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}
	item := Item{Key: "llamas", Data: []byte("llamas are great")}

	if err := k.Set(context.Background(), item); err != nil {
		t.Fatal(err)
	}

	foundItem, err := k.Get(context.Background(), "llamas")
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

	if err := k.Set(context.Background(), item); err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(context.Background(), item.Key); err != nil {
		t.Fatal(err)
	}
}

func TestFileKeyringUsesPortableFilenames(t *testing.T) {
	dir := t.TempDir()
	k := &fileKeyring{
		dir:          dir,
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	key := `token:default:user@example.com/<>:"\|?*%`
	if err := k.Set(context.Background(), Item{Key: key, Data: []byte("secret")}); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one keyring directory, got %d", len(entries))
	}
	if entries[0].Name() != fileKeyDir || !entries[0].IsDir() {
		t.Fatalf("expected %s directory, got %s", fileKeyDir, entries[0].Name())
	}

	entries, err = os.ReadDir(filepath.Join(dir, fileKeyDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one keyring file, got %d", len(entries))
	}
	if name := entries[0].Name(); strings.ContainsAny(name, `<>:"/\|?*%`) {
		t.Fatalf("keyring filename %q contains a reserved character", name)
	}

	foundItem, err := k.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if foundItem.Key != key || string(foundItem.Data) != "secret" {
		t.Fatalf("unexpected item: key=%q data=%q", foundItem.Key, foundItem.Data)
	}

	keys, err := k.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("expected key %q, got %v", key, keys)
	}
}

func TestFileKeyringReadsLegacyFilenames(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}
	key := "aws-sso-portal/awsapps/start"

	writeLegacyFile(t, k, Item{Key: key, Data: []byte("legacy")})

	foundItem, err := k.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if foundItem.Key != key || string(foundItem.Data) != "legacy" {
		t.Fatalf("unexpected legacy item: key=%q data=%q", foundItem.Key, foundItem.Data)
	}

	if _, err := k.Metadata(context.Background(), key); err != nil {
		t.Fatal(err)
	}

	keys, err := k.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("expected legacy key %q, got %v", key, keys)
	}
}

func TestFileKeyringRemovesLegacyAndPortableFilenames(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}
	key := `token/default/user@example.com`

	if err := k.Set(context.Background(), Item{Key: key, Data: []byte("portable")}); err != nil {
		t.Fatal(err)
	}
	writeLegacyFile(t, k, Item{Key: key, Data: []byte("legacy")})

	keys, err := k.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key {
		t.Fatalf("expected deduped key %q, got %v", key, keys)
	}

	filename, err := k.filename(key)
	if err != nil {
		t.Fatal(err)
	}
	legacyFilename, err := k.legacyFilename(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := k.Remove(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Fatalf("expected portable filename removed, got %v", err)
	}
	if _, err := os.Stat(legacyFilename); !os.IsNotExist(err) {
		t.Fatalf("expected legacy filename removed, got %v", err)
	}
	if err := k.Remove(context.Background(), key); err != ErrKeyNotFound {
		t.Fatalf("expected ErrKeyNotFound after removing both files, got %v", err)
	}
}

func TestFileKeyringLegacyFilenameDoesNotCollideWithPortableFilename(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	newKey := "portable"
	legacyKey := filenameEscape(newKey)
	writeLegacyFile(t, k, Item{Key: legacyKey, Data: []byte("legacy")})
	if err := k.Set(context.Background(), Item{Key: newKey, Data: []byte("portable")}); err != nil {
		t.Fatal(err)
	}

	newItem, err := k.Get(context.Background(), newKey)
	if err != nil {
		t.Fatal(err)
	}
	if newItem.Key != newKey || string(newItem.Data) != "portable" {
		t.Fatalf("unexpected portable item: key=%q data=%q", newItem.Key, newItem.Data)
	}

	legacyItem, err := k.Get(context.Background(), legacyKey)
	if err != nil {
		t.Fatal(err)
	}
	if legacyItem.Key != legacyKey || string(legacyItem.Data) != "legacy" {
		t.Fatalf("unexpected legacy item: key=%q data=%q", legacyItem.Key, legacyItem.Data)
	}

	keys, err := k.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != legacyKey || keys[1] != newKey {
		t.Fatalf("expected both keys, got %v", keys)
	}
}

func TestFileKeyringLegacyNamespaceFileStillReadable(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	writeLegacyFile(t, k, Item{Key: fileKeyDir, Data: []byte("legacy")})

	item, err := k.Get(context.Background(), fileKeyDir)
	if err != nil {
		t.Fatal(err)
	}
	if item.Key != fileKeyDir || string(item.Data) != "legacy" {
		t.Fatalf("unexpected legacy namespace item: key=%q data=%q", item.Key, item.Data)
	}

	keys, err := k.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != fileKeyDir {
		t.Fatalf("expected legacy namespace key, got %v", keys)
	}

	if err := k.Remove(context.Background(), fileKeyDir); err != nil {
		t.Fatal(err)
	}
	if err := k.Set(context.Background(), Item{Key: "new", Data: []byte("portable")}); err != nil {
		t.Fatal(err)
	}
}

func TestFileKeyringRemoveWhenEmpty(t *testing.T) {
	k := &fileKeyring{
		dir:          t.TempDir(),
		passwordFunc: FixedStringPrompt("no more secrets"),
	}

	err := k.Remove(context.Background(), "no-such-key")
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

	if _, err := k.Keys(context.Background()); err == nil {
		t.Fatal("expected file keyring to reject a file path")
	}
}

func TestFilenameWithBadChars(t *testing.T) {
	a := `abc/.././123<>:"\|?*%`
	e := filenameEscape(a)
	if strings.ContainsAny(e, `<>:"/\|?*%`) {
		t.Fatalf("filenameEscape returned non-portable filename %q", e)
	}

	b := filenameUnescape(e)
	if b != a {
		t.Fatal("Unexpected filenameEscape")
	}

	legacy := legacyFilenameEscape(a)
	if legacyFilenameUnescape(legacy) != a {
		t.Fatal("Unexpected legacyFilenameEscape")
	}
}

func writeLegacyFile(t *testing.T, k *fileKeyring, item Item) {
	t.Helper()

	bytes, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jose.Encrypt(string(bytes), jose.PBES2_HS256_A128KW, jose.A256GCM, "no more secrets", jose.Headers(map[string]interface{}{
		"created": "legacy",
	}))
	if err != nil {
		t.Fatal(err)
	}

	filename, err := k.legacyFilename(item.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
}
