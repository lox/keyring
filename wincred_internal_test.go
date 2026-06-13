//go:build windows
// +build windows

package keyring

import (
	"errors"
	"reflect"
	"testing"

	"github.com/danieljoos/wincred"
)

func TestWinCredGetTreatsNilCredentialAsMissing(t *testing.T) {
	originalGetCredential := getWinCredGenericCredential
	getWinCredGenericCredential = func(string) (*wincred.GenericCredential, error) {
		var missing *wincred.GenericCredential
		return missing, nil
	}
	t.Cleanup(func() {
		getWinCredGenericCredential = originalGetCredential
	})

	kr := &windowsKeyring{name: "test", prefix: "keyring"}

	_, err := kr.Get("missing")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestWinCredRemoveTreatsNilCredentialAsMissing(t *testing.T) {
	originalGetCredential := getWinCredGenericCredential
	getWinCredGenericCredential = func(string) (*wincred.GenericCredential, error) {
		var missing *wincred.GenericCredential
		return missing, nil
	}
	t.Cleanup(func() {
		getWinCredGenericCredential = originalGetCredential
	})

	kr := &windowsKeyring{name: "test", prefix: "keyring"}

	err := kr.Remove("missing")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestWinCredSetRejectsOversizedData(t *testing.T) {
	kr := &windowsKeyring{name: "test", prefix: "keyring"}

	err := kr.Set(Item{
		Key:  "large",
		Data: make([]byte, maxWinCredCredentialBlobSize+1),
	})
	if !errors.Is(err, ErrCredentialTooLarge) {
		t.Fatalf("expected ErrCredentialTooLarge, got %v", err)
	}
}

func TestWinCredKeysReturnsFilteredSortedKeys(t *testing.T) {
	originalListCredentials := listWinCredCredentials
	listWinCredCredentials = func(filter string) ([]*wincred.Credential, error) {
		if filter != "keyring:test:*" {
			t.Fatalf("unexpected filter %q", filter)
		}
		return []*wincred.Credential{
			{TargetName: "keyring:test:zebra"},
			nil,
			{TargetName: "other:test:ignored"},
			{TargetName: "keyring:test:alpaca"},
		}, nil
	}
	t.Cleanup(func() {
		listWinCredCredentials = originalListCredentials
	})

	kr := &windowsKeyring{name: "test", prefix: "keyring"}

	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{"alpaca", "zebra"}
	if !reflect.DeepEqual(keys, expected) {
		t.Fatalf("expected %#v, got %#v", expected, keys)
	}
}

func TestWinCredKeysReturnsListError(t *testing.T) {
	listErr := errors.New("list failed")
	originalListCredentials := listWinCredCredentials
	listWinCredCredentials = func(string) ([]*wincred.Credential, error) {
		return nil, listErr
	}
	t.Cleanup(func() {
		listWinCredCredentials = originalListCredentials
	})

	kr := &windowsKeyring{name: "test", prefix: "keyring"}

	_, err := kr.Keys()
	if !errors.Is(err, listErr) {
		t.Fatalf("expected list error, got %v", err)
	}
}
