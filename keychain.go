//go:build darwin && cgo
// +build darwin,cgo

package keyring

import (
	"errors"
	"fmt"

	gokeychain "github.com/99designs/go-keychain"
)

const (
	errSecUserCanceled       gokeychain.Error = -128
	errSecInvalidOwnerEdit   gokeychain.Error = -25244
	errSecMissingEntitlement gokeychain.Error = -34018
)

var errKeychainUpdateItemNotFound = errors.New("keychain item not found")

type keychain struct {
	path    string
	service string

	passwordFunc PromptFunc

	isSynchronizable         bool
	isAccessibleWhenUnlocked bool
	isTrusted                bool
}

func init() {
	supportedBackends[KeychainBackend] = opener(func(cfg Config) (backendKeyring, error) {
		if cfg.KeychainName != "" && cfg.KeychainSynchronizable {
			return nil, errKeychainSynchronizableWithCustomKeychain
		}

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

func (k *keychain) newAccountQuery(key string, synchronizable gokeychain.Synchronizable) gokeychain.Item {
	query := k.newItem()
	query.SetAccount(key)
	query.SetMatchLimit(gokeychain.MatchLimitOne)
	k.setMatchSearchList(&query)
	setSynchronizable(&query, synchronizable)
	return query
}

func (k *keychain) setMatchSearchList(item *gokeychain.Item) {
	if k.path == "" {
		return
	}

	item.SetMatchSearchList(gokeychain.NewWithPath(k.path))
}

func setSynchronizable(item *gokeychain.Item, synchronizable gokeychain.Synchronizable) {
	if synchronizable == gokeychain.SynchronizableDefault {
		return
	}

	item.SetSynchronizable(synchronizable)
}

func (k *keychain) synchronizableItemMode(item Item) gokeychain.Synchronizable {
	if !k.isSynchronizable {
		return gokeychain.SynchronizableDefault
	}
	if item.KeychainNotSynchronizable {
		return gokeychain.SynchronizableNo
	}

	return gokeychain.SynchronizableYes
}

func (k *keychain) synchronizableQueryModes() []gokeychain.Synchronizable {
	if !k.isSynchronizable {
		return []gokeychain.Synchronizable{gokeychain.SynchronizableDefault}
	}

	return []gokeychain.Synchronizable{
		gokeychain.SynchronizableYes,
		gokeychain.SynchronizableNo,
	}
}

func (k *keychain) updateSynchronizableModes(synchronizable gokeychain.Synchronizable) []gokeychain.Synchronizable {
	if !k.isSynchronizable {
		return []gokeychain.Synchronizable{gokeychain.SynchronizableDefault}
	}

	modes := []gokeychain.Synchronizable{synchronizable}
	for _, fallback := range k.synchronizableQueryModes() {
		if fallback == synchronizable {
			continue
		}
		modes = append(modes, fallback)
	}

	return modes
}

func isKeychainNotFound(err error) bool {
	return err == gokeychain.ErrorItemNotFound || err == gokeychain.ErrorNoSuchKeychain
}

func isMissingSynchronizableEntitlement(err error) bool {
	return errors.Is(err, errSecMissingEntitlement)
}

func isKeychainAccessDenied(err error) bool {
	return errors.Is(err, errSecUserCanceled) ||
		errors.Is(err, errSecInvalidOwnerEdit) ||
		errors.Is(err, errSecMissingEntitlement) ||
		errors.Is(err, gokeychain.ErrorAuthFailed) ||
		errors.Is(err, gokeychain.ErrorInteractionNotAllowed) ||
		errors.Is(err, gokeychain.ErrorNoAccessForItem)
}

func normalizeKeychainError(err error) error {
	if err == nil || errors.Is(err, ErrAccessDenied) {
		return err
	}
	if isKeychainAccessDenied(err) {
		return fmt.Errorf("%w: %w", ErrAccessDenied, err)
	}
	return err
}

func (k *keychain) queryAccount(key string, prepare func(*gokeychain.Item)) ([]gokeychain.QueryResult, error) {
	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		query := k.newAccountQuery(key, synchronizable)
		prepare(&query)

		results, err := gokeychain.QueryItem(query)
		if isKeychainNotFound(err) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err != nil {
			return nil, normalizeKeychainError(err)
		}
		if len(results) == 0 {
			continue
		}

		return results, nil
	}

	if firstErr != nil {
		return nil, normalizeKeychainError(firstErr)
	}

	return nil, ErrKeyNotFound
}

func (k *keychain) existingKeychain() (gokeychain.Keychain, error) {
	kc := gokeychain.NewWithPath(k.path)
	return kc, kc.Status()
}

func (k *keychain) Get(key string) (Item, error) {
	debugf("Querying keychain for service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := k.queryAccount(key, func(query *gokeychain.Item) {
		query.SetReturnAttributes(true)
		query.SetReturnData(true)
	})
	if err == ErrKeyNotFound {
		debugf("No results found")
		return Item{}, ErrKeyNotFound
	}
	if err != nil {
		debugf("Error: %#v", err)
		return Item{}, err
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
	debugf("Querying keychain for metadata of service=%q, account=%q, keychain=%q", k.service, key, k.path)
	results, err := k.queryAccount(key, func(query *gokeychain.Item) {
		query.SetReturnAttributes(true)
		query.SetReturnData(false)
	})
	if err == ErrKeyNotFound {
		debugf("No results found")
		return Metadata{}, ErrKeyNotFound
	}
	if err != nil {
		debugf("Error: %#v", err)
		return Metadata{}, err
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

func (k *keychain) newUpdateQuery(kc gokeychain.Keychain, account string, synchronizable gokeychain.Synchronizable) gokeychain.Item {
	queryItem := k.newItem()
	queryItem.SetAccount(account)
	queryItem.SetMatchLimit(gokeychain.MatchLimitOne)
	setSynchronizable(&queryItem, synchronizable)

	if k.path != "" {
		queryItem.SetMatchSearchList(kc)
	}

	return queryItem
}

func (k *keychain) updateItemInMode(kc gokeychain.Keychain, kcItem gokeychain.Item, account string, synchronizable gokeychain.Synchronizable) error {
	queryItem := k.newUpdateQuery(kc, account, synchronizable)
	queryItem.SetReturnAttributes(true)

	results, err := gokeychain.QueryItem(queryItem)
	if isKeychainNotFound(err) {
		return errKeychainUpdateItemNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to query keychain: %w", normalizeKeychainError(err))
	}
	if len(results) == 0 {
		return errKeychainUpdateItemNotFound
	}

	// Don't call SetAccess() as this will cause multiple prompts on update, even when we are not updating the AccessList
	kcItem.SetAccess(nil)

	updateQuery := k.newUpdateQuery(kc, account, synchronizable)
	if err := gokeychain.UpdateItem(updateQuery, kcItem); err != nil {
		return fmt.Errorf("failed to update item in keychain: %w", normalizeKeychainError(err))
	}

	return nil
}

func (k *keychain) updateItem(kc gokeychain.Keychain, kcItem gokeychain.Item, account string, synchronizable gokeychain.Synchronizable) error {
	var firstErr error
	for _, mode := range k.updateSynchronizableModes(synchronizable) {
		err := k.updateItemInMode(kc, kcItem, account, mode)
		if err == nil {
			if firstErr != nil {
				return firstErr
			}
			return nil
		}
		if errors.Is(err, errKeychainUpdateItemNotFound) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		return err
	}

	if firstErr != nil {
		return normalizeKeychainError(firstErr)
	}

	return errKeychainUpdateItemNotFound
}

func (k *keychain) removeOtherSynchronizableItems(kc gokeychain.Keychain, account string, keepSynchronizable gokeychain.Synchronizable) error {
	if !k.isSynchronizable {
		return nil
	}

	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		if synchronizable == keepSynchronizable {
			continue
		}

		item := k.newItem()
		item.SetAccount(account)
		setSynchronizable(&item, synchronizable)

		if k.path != "" {
			item.SetMatchSearchList(kc)
		}

		err := gokeychain.DeleteItem(item)
		if err == nil || isKeychainNotFound(err) {
			continue
		}
		if isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		return normalizeKeychainError(err)
	}

	if firstErr != nil {
		return normalizeKeychainError(firstErr)
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

	synchronizable := k.synchronizableItemMode(item)
	usesSynchronizableAttr := synchronizable != gokeychain.SynchronizableDefault
	setSynchronizable(&kcItem, synchronizable)

	if k.isAccessibleWhenUnlocked {
		kcItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	}

	isTrusted := k.isTrusted && !item.KeychainNotTrustApplication

	switch {
	case usesSynchronizableAttr:
		debugf("Keychain item has a synchronizable attribute and doesn't use legacy access ACLs")
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
		err = k.updateItem(kc, kcItem, item.Key, synchronizable)
	}

	if err != nil {
		return normalizeKeychainError(err)
	}

	return k.removeOtherSynchronizableItems(kc, item.Key, synchronizable)
}

func (k *keychain) Remove(key string) error {
	var kc gokeychain.Keychain

	if k.path != "" {
		var err error
		kc, err = k.existingKeychain()
		if err != nil {
			if err == gokeychain.ErrorNoSuchKeychain {
				return ErrKeyNotFound
			}
			return normalizeKeychainError(err)
		}
	}

	debugf("Removing keychain item service=%q, account=%q, keychain %q", k.service, key, k.path)
	removed := false
	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		item := k.newItem()
		item.SetAccount(key)
		setSynchronizable(&item, synchronizable)

		if k.path != "" {
			item.SetMatchSearchList(kc)
		}

		err := gokeychain.DeleteItem(item)
		if err == nil {
			removed = true
			continue
		}
		if isKeychainNotFound(err) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		return normalizeKeychainError(err)
	}
	if firstErr != nil {
		return normalizeKeychainError(firstErr)
	}
	if removed {
		return nil
	}

	return ErrKeyNotFound
}

func (k *keychain) Keys() ([]string, error) {
	var kc gokeychain.Keychain

	if k.path != "" {
		var err error
		kc, err = k.existingKeychain()
		if err != nil {
			if err == gokeychain.ErrorNoSuchKeychain {
				return []string{}, nil
			}
			return nil, normalizeKeychainError(err)
		}
	}

	debugf("Querying keychain for service=%q, keychain=%q", k.service, k.path)
	accountNames := []string{}
	seen := map[string]struct{}{}
	var firstErr error
	for _, synchronizable := range k.synchronizableQueryModes() {
		query := k.newItem()
		query.SetMatchLimit(gokeychain.MatchLimitAll)
		query.SetReturnAttributes(true)
		setSynchronizable(&query, synchronizable)

		if k.path != "" {
			query.SetMatchSearchList(kc)
		}

		results, err := gokeychain.QueryItem(query)
		if isKeychainNotFound(err) {
			continue
		}
		if k.isSynchronizable && isMissingSynchronizableEntitlement(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err != nil {
			return nil, normalizeKeychainError(err)
		}

		debugf("Found %d results", len(results))
		for _, r := range results {
			if _, ok := seen[r.Account]; ok {
				continue
			}
			seen[r.Account] = struct{}{}
			accountNames = append(accountNames, r.Account)
		}
	}

	if firstErr != nil {
		return nil, normalizeKeychainError(firstErr)
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
		return gokeychain.Keychain{}, normalizeKeychainError(err)
	}

	if k.passwordFunc == nil {
		debugf("Creating keychain %s with prompt", k.path)
		kc, err := gokeychain.NewKeychainWithPrompt(k.path)
		return kc, normalizeKeychainError(err)
	}

	passphrase, err := k.passwordFunc("Enter passphrase for keychain")
	if err != nil {
		return gokeychain.Keychain{}, err
	}

	debugf("Creating keychain %s with provided password", k.path)
	kc, err = gokeychain.NewKeychain(k.path, passphrase)
	return kc, normalizeKeychainError(err)
}
