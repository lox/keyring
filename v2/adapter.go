package keyring

import (
	"context"

	v1 "github.com/lox/keyring"
)

type v1Keyring struct {
	ring v1.Keyring
}

func (k v1Keyring) Get(ctx context.Context, key string) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	item, err := k.ring.Get(key)
	if err != nil {
		return Item{}, mapError(err)
	}
	return itemFromV1(item), nil
}

func (k v1Keyring) Set(ctx context.Context, item Item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return mapError(k.ring.Set(itemToV1(item)))
}

func (k v1Keyring) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return mapError(k.ring.Remove(key))
}

func (k v1Keyring) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, mapError(err)
	}
	return keys, nil
}

func (k v1Keyring) Metadata(ctx context.Context, key string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	metadata, err := k.ring.GetMetadata(key)
	if err != nil {
		return Metadata{}, mapError(err)
	}
	return metadataFromV1(key, metadata), nil
}

func itemToV1(item Item) v1.Item {
	return v1.Item{
		Key:         item.Key,
		Data:        item.Data,
		Label:       item.Label,
		Description: item.Description,
	}
}

func itemFromV1(item v1.Item) Item {
	return Item{
		Key:         item.Key,
		Data:        item.Data,
		Label:       item.Label,
		Description: item.Description,
	}
}

func metadataFromV1(key string, metadata v1.Metadata) Metadata {
	out := Metadata{
		Key:              key,
		ModificationTime: metadata.ModificationTime,
	}
	if metadata.Item != nil {
		out.Key = metadata.Key
		out.Label = metadata.Label
		out.Description = metadata.Description
	}
	return out
}
