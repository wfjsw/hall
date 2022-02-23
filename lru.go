package main

import (
	"sync"

	"github.com/hashicorp/golang-lru/simplelru"
)

// LRU is a thread-safe fixed size LRU cache.
type LRU struct {
	lru  simplelru.LRUCache
	lock sync.RWMutex
}

// NewLRUCache creates an LRU of the given size.
func NewLRUCache(size int) (*LRU, error) {
	return NewLRUCacheWithEvict(size, nil)
}

// NewLRUCache creates an LRU of the given size with eviction callback.
func NewLRUCacheWithEvict(size int, onEvicted func(key interface{}, value interface{})) (*LRU, error) {
	lru, err := simplelru.NewLRU(size, onEvicted)
	if err != nil {
		return nil, err
	}
	c := &LRU{
		lru: lru,
	}
	return c, nil
}

// Purge is used to completely clear the cache.
func (c *LRU) Purge() {
	c.lock.Lock()
	c.lru.Purge()
	c.lock.Unlock()
}

// Add adds a value to the cache. Returns true if an eviction occurred.
func (c *LRU) Add(key, value interface{}) (evicted bool) {
	c.lock.Lock()
	evicted = c.lru.Add(key, value)
	c.lock.Unlock()
	return evicted
}

// Get looks up a key's value from the cache.
func (c *LRU) Get(key interface{}) (value interface{}, ok bool) {
	c.lock.Lock()
	value, ok = c.lru.Get(key)
	c.lock.Unlock()
	return value, ok
}

// Contains checks if a key is in the cache, without updating the
// recent-ness or deleting it for being stale.
func (c *LRU) Contains(key interface{}) bool {
	c.lock.RLock()
	containKey := c.lru.Contains(key)
	c.lock.RUnlock()
	return containKey
}

// Peek returns the key value (or undefined if not found) without updating
// the "recently used"-ness of the key.
func (c *LRU) Peek(key interface{}) (value interface{}, ok bool) {
	c.lock.RLock()
	value, ok = c.lru.Peek(key)
	c.lock.RUnlock()
	return value, ok
}

// ContainsOrAdd checks if a key is in the cache without updating the
// recent-ness or deleting it for being stale, and if not, adds the value.
// Returns whether found and whether an eviction occurred.
func (c *LRU) ContainsOrAdd(key, value interface{}) (ok, evicted bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.lru.Contains(key) {
		return true, false
	}
	evicted = c.lru.Add(key, value)
	return false, evicted
}

// PeekOrAdd checks if a key is in the cache without updating the
// recent-ness or deleting it for being stale, and if not, adds the value.
// Returns whether found and whether an eviction occurred.
func (c *LRU) PeekOrAdd(key, value interface{}) (previous interface{}, ok, evicted bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	previous, ok = c.lru.Peek(key)
	if ok {
		return previous, true, false
	}

	evicted = c.lru.Add(key, value)
	return nil, false, evicted
}

// Remove removes the provided key from the cache.
func (c *LRU) Remove(key interface{}) (present bool) {
	c.lock.Lock()
	present = c.lru.Remove(key)
	c.lock.Unlock()
	return
}

// RemoveWithCallback choose keys to remove by a callback function.
func (c *LRU) RemoveWithCallback(fn func(key interface{}) bool) (count int) {
	c.lock.Lock()
	count = 0
	for _, key := range c.lru.Keys() {
		if fn(key) {
			present := c.lru.Remove(key)
			if present {
				count++
			}
		}
	}
	c.lock.Unlock()
	return
}

// Resize changes the cache size.
func (c *LRU) Resize(size int) (evicted int) {
	c.lock.Lock()
	evicted = c.lru.Resize(size)
	c.lock.Unlock()
	return evicted
}

// RemoveOldest removes the oldest item from the cache.
func (c *LRU) RemoveOldest() (key interface{}, value interface{}, ok bool) {
	c.lock.Lock()
	key, value, ok = c.lru.RemoveOldest()
	c.lock.Unlock()
	return
}

// GetOldest returns the oldest entry
func (c *LRU) GetOldest() (key interface{}, value interface{}, ok bool) {
	c.lock.Lock()
	key, value, ok = c.lru.GetOldest()
	c.lock.Unlock()
	return
}

// Keys returns a slice of the keys in the cache, from oldest to newest.
func (c *LRU) Keys() []interface{} {
	c.lock.RLock()
	keys := c.lru.Keys()
	c.lock.RUnlock()
	return keys
}

// Len returns the number of items in the cache.
func (c *LRU) Len() int {
	c.lock.RLock()
	length := c.lru.Len()
	c.lock.RUnlock()
	return length
}
