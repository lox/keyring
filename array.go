package keyring

import "context"

// ArrayKeyring is a mock/non-secure backend that meets the Keyring interface.
// It is intended to be used to aid unit testing of code that relies on the
// package. NOTE: Do not use in production code.
type ArrayKeyring struct {
	items map[string]Item
}

// NewArrayKeyring returns an ArrayKeyring, optionally constructed with an
// initial slice of items.
func NewArrayKeyring(initial []Item) *ArrayKeyring {
	return newArrayKeyring(context.Background(), initial)
}

func newArrayKeyring(ctx context.Context, initial []Item) *ArrayKeyring {
	kr := &ArrayKeyring{}
	for _, item := range initial {
		_ = kr.Set(ctx, item)
	}
	return kr
}

// Get returns an Item matching key.
func (k *ArrayKeyring) Get(ctx context.Context, key string) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	if item, ok := k.items[key]; ok {
		return item, nil
	}
	return Item{}, ErrNotFound
}

// Set stores an item on the mock Keyring.
func (k *ArrayKeyring) Set(ctx context.Context, item Item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if k.items == nil {
		k.items = map[string]Item{}
	}
	k.items[item.Key] = item
	return nil
}

// Remove deletes an Item from the Keyring.
func (k *ArrayKeyring) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	delete(k.items, key)
	return nil
}

// Keys provides a slice of all Item keys on the Keyring.
func (k *ArrayKeyring) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(k.items))
	for key := range k.items {
		keys = append(keys, key)
	}
	return keys, nil
}

// Metadata returns ErrMetadataNeedsUnlock for the in-memory backend.
func (k *ArrayKeyring) Metadata(ctx context.Context, _ string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	return Metadata{}, ErrMetadataNeedsUnlock
}
