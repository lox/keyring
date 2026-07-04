package keyring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTimeoutReturnsWhenOperationBlocks(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	ring := Timeout(&blockingKeyring{block: block}, 10*time.Millisecond)

	_, err := ring.Keys(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if !strings.Contains(err.Error(), "list keys") {
		t.Fatalf("expected operation in error, got %v", err)
	}
}

func TestTimeoutPreservesMetadataCapability(t *testing.T) {
	ctx := context.Background()

	withoutMetadata := Timeout(&plainKeyring{}, time.Second)
	if _, ok := withoutMetadata.(MetadataReader); ok {
		t.Fatal("expected metadata capability to stay absent")
	}

	withMetadata := Timeout(newArrayKeyring(ctx, nil), time.Second)
	reader, ok := withMetadata.(MetadataReader)
	if !ok {
		t.Fatal("expected metadata capability to be preserved")
	}
	if _, err := reader.Metadata(ctx, "llamas"); !errors.Is(err, ErrMetadataNeedsUnlock) {
		t.Fatalf("expected metadata error from inner keyring, got %v", err)
	}
}

func TestTimeoutPreservesClose(t *testing.T) {
	inner := &closableKeyring{}
	ring := Timeout(inner, time.Second)

	unwrapper, ok := ring.(interface{ Unwrap() Keyring })
	if !ok {
		t.Fatal("expected unwrap capability")
	}
	if unwrapper.Unwrap() != inner {
		t.Fatal("expected unwrap to return inner keyring")
	}

	closer, ok := ring.(interface{ Close() error })
	if !ok {
		t.Fatal("expected close capability to be preserved")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !inner.closed {
		t.Fatal("expected inner keyring to be closed")
	}
}

type blockingKeyring struct {
	block <-chan struct{}
}

func (k *blockingKeyring) wait() {
	<-k.block
}

func (k *blockingKeyring) Get(context.Context, string) (Item, error) {
	k.wait()
	return Item{}, ErrNotFound
}

func (k *blockingKeyring) Set(context.Context, Item) error {
	k.wait()
	return nil
}

func (k *blockingKeyring) Remove(context.Context, string) error {
	k.wait()
	return nil
}

func (k *blockingKeyring) Keys(context.Context) ([]string, error) {
	k.wait()
	return nil, nil
}

type plainKeyring struct{}

func (k *plainKeyring) Get(ctx context.Context, _ string) (Item, error) {
	if err := ctx.Err(); err != nil {
		return Item{}, err
	}
	return Item{}, ErrNotFound
}

func (k *plainKeyring) Set(ctx context.Context, _ Item) error {
	return ctx.Err()
}

func (k *plainKeyring) Remove(ctx context.Context, _ string) error {
	return ctx.Err()
}

func (k *plainKeyring) Keys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

type closableKeyring struct {
	plainKeyring
	closed bool
}

func (k *closableKeyring) Close() error {
	k.closed = true
	return nil
}
