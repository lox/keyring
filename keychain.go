//go:build darwin && cgo
// +build darwin,cgo

package keyring

import (
	"errors"
	"fmt"

	gokeychain "github.com/99designs/go-keychain"
)

type keychain struct {
	path    string
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
	isTrusted                bool
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (Keyring, error) {
		kc := &keychain{
			service:          cfg.ServiceName,
			passwordFunc:     cfg.KeychainPasswordFunc,
			isSynchronizable: cfg.KeychainSynchronizable,

			// Set the isAccessibleWhenUnlocked to the boolean value of
			// KeychainAccessibleWhenUnlocked is a shorthand for setting the accessibility value.
			// See: https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked
			isAccessibleWhenUnlocked: cfg.KeychainAccessibleWhenUnlocked,
		}
		if cfg.KeychainName != "" {
			kc.path = cfg.KeychainName + ".keychain"
		}
		if cfg.KeychainTrustApplication {
			kc.isTrusted = true
		}
		return kc, nil
	})
}

func (k *keychain) newItem() gokeychain.Item {
	item := gokeychain.NewItem()
	item.SetSecClass(gokeychain.SecClassGenericPassword)
	item.SetService(k.service)
	return item
}

func (k *keychain) newAccountQuery(key string) gokeychain.Item {
	query := k.newItem()
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	k.setMatchSearchList(&query)
	k.setSynchronizableMatch(&query, k.isSynchronizable)
	return query
}

func (k *keychain) setMatchSearchList(item *gokeychain.Item) {
	if k.path == "" {
		return
	}

	item.SetMatchSearchList(gokeychain.NewWithPath(k.path))
}

func (k *keychain) setSynchronizableMatch(item *gokeychain.Item, isSynchronizable bool) {
	if !isSynchronizable {
		return
	}

	item.SetSynchronizable(gokeychain.SynchronizableAny)
}

func (k *keychain) existingKeychain() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)
	return kc, kc.Status()
}

func (k *keychain) Get(key string) (Item, error) {
	query := k.newAccountQuery(key)
	query.SetReturnAttributes(true)
	query.SetReturnData(true)

	debugf("Querying keychain for service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || err == gokeychain.ErrorNoSuchKeychain {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}

	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
	}
	if len(results) == 0 {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}

	item := Item{
		Key:         key,
		Data:        results[0].Data,
		Label:       results[0].Label,
		Description: results[0].Description,
	}

	debugf("Found item %q", results[0].Label)
	return item, nil
}

func (k *keychain) GetMetadata(key string) (Metadata, error) {
	query := k.newAccountQuery(key)
	query.SetReturnAttributes(true)
	query.SetReturnData(false)

	debugf("Querying keychain for metadata of service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := gokeychain.QueryItem(query)
	if err == gokeychain.ErrorItemNotFound || err == gokeychain.ErrorNoSuchKeychain {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	}
	if err != nil {
		debugf("Error: %#v", err)
		return Metadata{}, err
	}
	if len(results) == 0 {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	}

	md := Metadata{
		Item: &Item{
			Key:         key,
			Label:       results[0].Label,
			Description: results[0].Description,
		},
		ModificationTime: results[0].ModificationDate,
	}

	debugf("Found metadata for %q", md.Label)

	return md, nil
}

func (k *keychain) updateItem(kc gokeychain.Keychain, kcItem gokeychain.Item, account string) error {
	queryItem := k.newItem()
	queryItem.SetAccount(account)
	queryItem.SetMatchLimit(gokeychain.MatchLimitOne)
	queryItem.SetReturnAttributes(true)
	k.setSynchronizableMatch(&queryItem, k.isSynchronizable)

	if k.path != "" {
		queryItem.SetMatchSearchList(kc)
	}

	results, err := gokeychain.QueryItem(queryItem)
	if err != nil {
		return fmt.Errorf("failed to query keychain: %v", err)
	}
	if len(results) == 0 {
		return errors.New("no results")
	}

	// Don't call SetAccess() as this will cause multiple prompts on update, even when we are not updating the AccessList
	kcItem.SetAccess(nil)

	if err := gokeychain.UpdateItem(queryItem, kcItem); err != nil {
		return fmt.Errorf("failed to update item in keychain: %v", err)
	}

	return nil
}

func (k *keychain) Set(item Item) error {
	var kc gokeychain.Keychain

	// when we are setting a value, we create or open
	if k.path != "" {
		var err error
		kc, err = k.createOrOpen()
		if err != nil {
			return err
		}
	}

	kcItem := k.newItem()
	kcItem.SetAccount(item.Key)
	kcItem.SetLabel(item.Label)
	kcItem.SetDescription(item.Description)
	kcItem.SetData(item.Data)

	if k.path != "" {
		kcItem.UseKeychain(kc)
	}

	isSynchronizable := k.isSynchronizable && !item.KeychainNotSynchronizable
	if isSynchronizable {
		kcItem.SetSynchronizable(gokeychain.SynchronizableYes)
	}

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	isTrusted := k.isTrusted && !item.KeychainNotTrustApplication

	switch {
	case isSynchronizable:
		debugf("Keychain item is synchronizable and doesn't use legacy access ACLs")
	case isTrusted:
		debugf("Keychain item trusts keyring")
		kcItem.SetAccess(&gokeychain.Access{
			Label:               item.Label,
			TrustedApplications: nil,
		})
	default:
		debugf("Keychain item doesn't trust keyring")
		kcItem.SetAccess(&gokeychain.Access{
			Label:               item.Label,
			TrustedApplications: []string{},
		})
	}

	debugf("Adding service=%q, label=%q, account=%q, trusted=%v to osx keychain %q", k.service, item.Label, item.Key, isTrusted, k.path)

	err := gokeychain.AddItem(kcItem)

	if err == gokeychain.ErrorDuplicateItem {
		debugf("Item already exists, updating")
		err = k.updateItem(kc, kcItem, item.Key)
	}

	if err != nil {
		return err
	}

	return nil
}

func (k *keychain) Remove(key string) error {
	item := k.newItem()
	item.SetAccount(key)
	k.setSynchronizableMatch(&item, k.isSynchronizable)

	if k.path != "" {
		kc, err := k.existingKeychain()
		if err != nil {
			if err == gokeychain.ErrorNoSuchKeychain {
				return ErrKeyNotFound
			}
			return err
		}

		item.SetMatchSearchList(kc)
	}

	debugf("Removing keychain item service=%q, account=%q, keychain %q", k.service, key, k.path)
	err := gokeychain.DeleteItem(item)
	if err == gokeychain.ErrorItemNotFound {
		return ErrKeyNotFound
	}

	return err
}

func (k *keychain) Keys() ([]string, error) {
	query := k.newItem()
	query.SetMatchLimit(gokeychain.MatchLimitAll)
	query.SetReturnAttributes(true)
	k.setSynchronizableMatch(&query, k.isSynchronizable)

	if k.path != "" {
		kc, err := k.existingKeychain()
		if err != nil {
			if err == gokeychain.ErrorNoSuchKeychain {
				return []string{}, nil
			}
			return nil, err
		}

		query.SetMatchSearchList(kc)
	}

	debugf("Querying keychain for service=%q, keychain=%q", k.service, k.path)
	results, err := gokeychain.QueryItem(query)
	if err != nil {
		return nil, err
	}

	debugf("Found %d results", len(results))
	accountNames := make([]string, len(results))
	for idx, r := range results {
		accountNames[idx] = r.Account
	}

	return accountNames, nil
}

func (k *keychain) createOrOpen() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)

	debugf("Checking keychain status")
	err := kc.Status()
	if err == nil {
		debugf("Keychain status returned nil, keychain exists")
		return kc, nil
	}

	debugf("Keychain status returned error: %v", err)

	if err != gokeychain.ErrorNoSuchKeychain {
		return gokeychain.Keychain{}, err
	}

	if k.passwordFunc == nil {
		debugf("Creating keychain %s with prompt", k.path)
		return gokeychain.NewKeychainWithPrompt(k.path)
	}

	passphrase, err := k.passwordFunc("Enter passphrase for keychain")
	if err != nil {
		return gokeychain.Keychain{}, err
	}

	debugf("Creating keychain %s with provided password", k.path)
	return gokeychain.NewKeychain(k.path, passphrase)
}
