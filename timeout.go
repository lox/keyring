package keyring

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Timeout returns a keyring that applies timeout to each operation.
//
// Timeout does not apply to Open. If a provider ignores context cancellation,
// the worker goroutine may remain blocked until that provider returns.
func Timeout(ring Keyring, timeout time.Duration) Keyring {
	if ring == nil {
		return nil
	}

	base := &timeoutKeyring{
		inner:   ring,
		timeout: timeout,
	}
	metadata, hasMetadata := ring.(MetadataReader)
	closer, hasCloser := ring.(io.Closer)

	switch {
	case hasMetadata && hasCloser:
		return &timeoutMetadataCloserKeyring{
			timeoutMetadataKeyring: &timeoutMetadataKeyring{
				timeoutKeyring: base,
				metadata:       metadata,
			},
			closer: closer,
		}
	case hasMetadata:
		return &timeoutMetadataKeyring{
			timeoutKeyring: base,
			metadata:       metadata,
		}
	case hasCloser:
		return &timeoutCloserKeyring{
			timeoutKeyring: base,
			closer:         closer,
		}
	default:
		return base
	}
}

type timeoutKeyring struct {
	inner   Keyring
	timeout time.Duration
}

func (k *timeoutKeyring) Unwrap() Keyring {
	return k.inner
}

func (k *timeoutKeyring) Get(ctx context.Context, key string) (Item, error) {
	return withOperationTimeout(ctx, k.timeout, "get item", func(ctx context.Context) (Item, error) {
		return k.inner.Get(ctx, key)
	})
}

func (k *timeoutKeyring) Set(ctx context.Context, item Item) error {
	_, err := withOperationTimeout(ctx, k.timeout, "set item", func(ctx context.Context) (struct{}, error) {
		return struct{}{}, k.inner.Set(ctx, item)
	})
	return err
}

func (k *timeoutKeyring) Remove(ctx context.Context, key string) error {
	_, err := withOperationTimeout(ctx, k.timeout, "remove item", func(ctx context.Context) (struct{}, error) {
		return struct{}{}, k.inner.Remove(ctx, key)
	})
	return err
}

func (k *timeoutKeyring) Keys(ctx context.Context) ([]string, error) {
	return withOperationTimeout(ctx, k.timeout, "list keys", func(ctx context.Context) ([]string, error) {
		return k.inner.Keys(ctx)
	})
}

type timeoutMetadataKeyring struct {
	*timeoutKeyring
	metadata MetadataReader
}

func (k *timeoutMetadataKeyring) Metadata(ctx context.Context, key string) (Metadata, error) {
	return withOperationTimeout(ctx, k.timeout, "read metadata", func(ctx context.Context) (Metadata, error) {
		return k.metadata.Metadata(ctx, key)
	})
}

type timeoutCloserKeyring struct {
	*timeoutKeyring
	closer io.Closer
}

func (k *timeoutCloserKeyring) Close() error {
	return k.closer.Close()
}

type timeoutMetadataCloserKeyring struct {
	*timeoutMetadataKeyring
	closer io.Closer
}

func (k *timeoutMetadataCloserKeyring) Close() error {
	return k.closer.Close()
}

func withOperationTimeout[T any](
	ctx context.Context,
	timeout time.Duration,
	operation string,
	fn func(context.Context) (T, error),
) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if timeout <= 0 {
		return zero, fmt.Errorf("keyring %s timed out after %s: %w", operation, timeout, context.DeadlineExceeded)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	type result struct {
		value T
		err   error
	}

	ch := make(chan result, 1)
	go func() {
		value, err := fn(ctx)
		ch <- result{value: value, err: err}
	}()

	select {
	case res := <-ch:
		return res.value, res.err
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-timer.C:
		cancel()
		return zero, fmt.Errorf("keyring %s timed out after %s: %w", operation, timeout, context.DeadlineExceeded)
	}
}
