package connector

import (
	"context"
	"maps"
	"slices"
	"sync"

	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

var _ sessions.SessionStore = (*memorySessionStore)(nil)

// memorySessionStore is an in-memory sessions.SessionStore that honors sessions.WithPrefix.
type memorySessionStore struct {
	mu     sync.Mutex
	values map[string][]byte
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{values: map[string][]byte{}}
}

func fullKey(ctx context.Context, key string, opts []sessions.SessionStoreOption) (string, error) {
	bag := &sessions.SessionStoreBag{}
	for _, opt := range opts {
		if err := opt(ctx, bag); err != nil {
			return "", err
		}
	}
	return bag.Prefix + key, nil
}

func (store *memorySessionStore) Get(ctx context.Context, key string, opts ...sessions.SessionStoreOption) ([]byte, bool, error) {
	storeKey, err := fullKey(ctx, key, opts)
	if err != nil {
		return nil, false, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.values[storeKey]
	return value, found, nil
}

// GetMany returns only the keys it holds; the second result lists keys left
// unprocessed (a size-limit overflow in the real store), never absent ones.
func (store *memorySessionStore) GetMany(ctx context.Context, keys []string, opts ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	found := map[string][]byte{}
	for _, key := range keys {
		value, ok, err := store.Get(ctx, key, opts...)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			found[key] = value
		}
	}
	return found, nil, nil
}

func (store *memorySessionStore) Set(ctx context.Context, key string, value []byte, opts ...sessions.SessionStoreOption) error {
	return store.SetMany(ctx, map[string][]byte{key: value}, opts...)
}

func (store *memorySessionStore) SetMany(ctx context.Context, values map[string][]byte, opts ...sessions.SessionStoreOption) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	for key, value := range values {
		storeKey, err := fullKey(ctx, key, opts)
		if err != nil {
			return err
		}
		store.values[storeKey] = slices.Clone(value)
	}
	return nil
}

func (store *memorySessionStore) Delete(ctx context.Context, key string, opts ...sessions.SessionStoreOption) error {
	storeKey, err := fullKey(ctx, key, opts)
	if err != nil {
		return err
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, storeKey)
	return nil
}

func (store *memorySessionStore) Clear(_ context.Context, _ ...sessions.SessionStoreOption) error {
	store.mu.Lock()
	defer store.mu.Unlock()

	clear(store.values)
	return nil
}

func (store *memorySessionStore) GetAll(_ context.Context, _ string, _ ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	return maps.Clone(store.values), "", nil
}
