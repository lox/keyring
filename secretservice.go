//go:build linux
// +build linux

package keyring

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var newLibSecretService = newSecretService

func init() {
	supportedBackends[SecretServiceBackend] = opener(func(cfg Config) (backendKeyring, error) {
		if cfg.ServiceName == "" {
			cfg.ServiceName = "secret-service"
		}
		if cfg.LibSecretCollectionName == "" {
			cfg.LibSecretCollectionName = cfg.ServiceName
		}

		service, err := newLibSecretService()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}

		ring := &secretsKeyring{
			name:    cfg.LibSecretCollectionName,
			service: service,
		}

		if err := ring.openSecrets(); err != nil {
			_ = ring.Close()
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return ring, nil
	})
}

type secretsKeyring struct {
	name       string
	service    *secretService
	collection *secretCollection
	session    *secretSession
}

var errCollectionNotFound = errors.New("collection does not exist, please add a key first")

func decodeKeyringString(src string) string {
	var dst strings.Builder
	for i := 0; i < len(src); i++ {
		if src[i] != '_' {
			dst.WriteString(string(src[i]))
		} else {
			if i+3 > len(src) {
				return src
			}
			hexstring := src[i+1 : i+3]
			decoded, err := hex.DecodeString(hexstring)
			if err != nil {
				return src
			}
			dst.Write(decoded)
			i += 2
		}
	}
	return dst.String()
}

func (k *secretsKeyring) openSecrets() error {
	session, err := k.service.Open()
	if err != nil {
		return err
	}
	k.session = session
	k.collection = nil

	// get the collection if it already exists
	collections, err := k.service.Collections()
	if err != nil {
		return err
	}

	path := secretServiceDBusPath + "/collection/" + k.name

	for _, collection := range collections {
		if decodeKeyringString(string(collection.Path())) == path {
			c := collection // fix variable into the local variable to ensure it's referenced correctly, see https://github.com/kyoh86/exportloopref
			k.collection = &c
			return nil
		}
	}

	return nil
}

func (k *secretsKeyring) openCollection() error {
	if err := k.openSecrets(); err != nil {
		return err
	}

	if k.collection == nil {
		return errCollectionNotFound
		// return &secretsError{fmt.Sprintf(
		// 	"The collection %q does not exist. Please add a key first",
		// 	k.name,
		// )}
	}

	return nil
}

func (k *secretsKeyring) Get(key string) (Item, error) {
	if err := k.openCollection(); err != nil {
		if err == errCollectionNotFound {
			return Item{}, ErrKeyNotFound
		}
		return Item{}, err
	}

	items, err := k.collection.SearchItems(key)
	if err != nil {
		return Item{}, err
	}

	if len(items) == 0 {
		return Item{}, ErrKeyNotFound
	}

	// use the first item whenever there are multiples
	// with the same profile name
	item := items[0]

	locked, err := item.Locked()
	if err != nil {
		return Item{}, err
	}

	if locked {
		if err := k.service.Unlock(item); err != nil {
			return Item{}, err
		}
	}

	secret, err := item.GetSecret(k.session)
	if err != nil {
		return Item{}, err
	}

	// pack the secret into the item
	var ret Item
	if err = json.Unmarshal(secret.Value, &ret); err != nil {
		return Item{}, err
	}

	return ret, err
}

// GetMetadata for Secret Service returns an error indicating that it's
// unsupported for this backend.
//
// Secret Service has item attributes, but no automatically maintained
// last-modification timestamp. To use those attributes, this package would need
// a SetMetadata API too.
func (k *secretsKeyring) GetMetadata(_ string) (Metadata, error) {
	return Metadata{}, ErrMetadataNeedsCredentials
}

func (k *secretsKeyring) Close() error {
	if k.service == nil {
		return nil
	}
	err := k.service.Close()
	k.service = nil
	k.collection = nil
	k.session = nil
	return err
}

func (k *secretsKeyring) Set(item Item) error {
	err := k.openSecrets()
	if err != nil {
		return err
	}

	// create the collection if it doesn't already exist
	if k.collection == nil {
		collection, err := k.service.CreateCollection(k.name)
		if err != nil {
			return err
		}

		k.collection = collection
	}

	if err := k.ensureCollectionUnlocked(); err != nil {
		return err
	}

	// create the new item
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}

	secret := newSecret(k.session, []byte{}, data, "application/json")

	if _, err := k.collection.CreateItem(item.Key, secret, true); err != nil {
		return err
	}

	return nil
}

func firstSecretServiceItem(items []secretItem) (*secretItem, error) {
	if len(items) == 0 {
		return nil, ErrKeyNotFound
	}

	return &items[0], nil
}

func (k *secretsKeyring) Remove(key string) error {
	if err := k.openCollection(); err != nil {
		if err == errCollectionNotFound {
			return ErrKeyNotFound
		}
		return err
	}

	items, err := k.collection.SearchItems(key)
	if err != nil {
		return err
	}

	// we dont want to delete more than one anyway
	// so just get the first item found
	item, err := firstSecretServiceItem(items)
	if err != nil {
		return err
	}

	locked, err := item.Locked()
	if err != nil {
		return err
	}

	if locked {
		if err := k.service.Unlock(item); err != nil {
			return err
		}
	}

	if err := item.Delete(); err != nil {
		return err
	}

	return nil
}

func (k *secretsKeyring) Keys() ([]string, error) {
	if err := k.openCollection(); err != nil {
		if err == errCollectionNotFound {
			return []string{}, nil
		}
		return nil, err
	}
	if err := k.ensureCollectionUnlocked(); err != nil {
		return nil, err
	}
	items, err := k.collection.Items()
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for _, item := range items {
		label, err := item.Label() // FIXME: err is being silently ignored
		if err == nil {
			keys = append(keys, label)
		}
	}
	return keys, nil
}

// deleteCollection deletes the keyring's collection if it exists. This is mainly to support testing.
func (k *secretsKeyring) deleteCollection() error {
	if err := k.openCollection(); err != nil {
		return err
	}
	return k.collection.Delete()
}

// unlock the collection if it's locked
func (k *secretsKeyring) ensureCollectionUnlocked() error {
	locked, err := k.collection.Locked()
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	return k.service.Unlock(k.collection)
}
