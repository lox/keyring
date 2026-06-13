package keyring

import "context"

type backendAdapter struct {
	ring backendKeyring
}

func (k backendAdapter) Get(ctx context.Context, key string) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	item, err := k.ring.Get(key)
	if err != nil {
		return Item{}, mapError(err)
	}
	return item, nil
}

func (k backendAdapter) Set(ctx context.Context, item Item) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return mapError(k.ring.Set(item))
}

func (k backendAdapter) Remove(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return mapError(k.ring.Remove(key))
}

func (k backendAdapter) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, mapError(err)
	}
	return keys, nil
}

func (k backendAdapter) Metadata(ctx context.Context, key string) (Metadata, error) {
	if err := ctx.Err(); err != nil {
		return Metadata{}, err
	}
	metadata, err := k.ring.GetMetadata(key)
	if err != nil {
		return Metadata{}, mapError(err)
	}
	return metadata, nil
}
