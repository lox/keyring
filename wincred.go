//go:build windows
// +build windows

package keyring

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/danieljoos/wincred"
)

// CRED_MAX_CREDENTIAL_BLOB_SIZE for generic credentials.
const maxWinCredCredentialBlobSize = 5 * 512

var (
	getWinCredGenericCredential = wincred.GetGenericCredential
	listWinCredCredentials      = wincred.FilteredList
	newWinCredGenericCredential = wincred.NewGenericCredential
)

type windowsKeyring struct {
	name   string
	prefix string
}

func init() {
	supportedBackends[WinCredBackend] = opener(func(cfg Config) (backendKeyring, error) {
		name := cfg.ServiceName
		if name == "" {
			name = "default"
		}

		prefix := cfg.WinCredPrefix
		if prefix == "" {
			prefix = "keyring"
		}

		return &windowsKeyring{
			name:   name,
			prefix: prefix,
		}, nil
	})
}

func (k *windowsKeyring) Get(key string) (Item, error) {
	cred, err := getWinCredGenericCredential(k.credentialName(key))
	if err != nil {
		if errors.Is(err, wincred.ErrElementNotFound) {
			return Item{}, ErrKeyNotFound
		}
		return Item{}, err
	}

	return itemFromWinCred(key, cred)
}

func itemFromWinCred(key string, cred *wincred.GenericCredential) (Item, error) {
	if cred == nil {
		return Item{}, ErrKeyNotFound
	}

	return Item{
		Key:  key,
		Data: cred.CredentialBlob,
	}, nil
}

// GetMetadata for pass returns an error indicating that it's unsupported
// for this backend.
// TODO: This is a stub. Look into whether pass would support metadata in a usable way for keyring.
func (k *windowsKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNotSupported
}

func (k *windowsKeyring) Set(item Item) error {
	if len(item.Data) > maxWinCredCredentialBlobSize {
		return fmt.Errorf("%w: wincred supports at most %d bytes", ErrCredentialTooLarge, maxWinCredCredentialBlobSize)
	}

	cred := newWinCredGenericCredential(k.credentialName(item.Key))
	cred.CredentialBlob = item.Data
	return cred.Write()
}

func (k *windowsKeyring) Remove(key string) error {
	cred, err := getWinCredGenericCredential(k.credentialName(key))
	if err != nil {
		if errors.Is(err, wincred.ErrElementNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	if cred == nil {
		return ErrKeyNotFound
	}
	return cred.Delete()
}

func (k *windowsKeyring) Keys() ([]string, error) {
	prefix := k.credentialName("")
	creds, err := listWinCredCredentials(prefix + "*")
	if err != nil {
		return nil, err
	}

	results := []string{}
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		if strings.HasPrefix(cred.TargetName, prefix) {
			results = append(results, strings.TrimPrefix(cred.TargetName, prefix))
		}
	}
	sort.Strings(results)

	return results, nil
}

func (k *windowsKeyring) credentialName(key string) string {
	return k.prefix + ":" + k.name + ":" + key
}
