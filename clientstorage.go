package main

import (
	"math"
	"sync"
)

type ClientStorage struct {
	mu   sync.RWMutex
	m    map[uint32]*Client
	mseq []*Client
}

func NewClientStorage(initialSize int) (storage *ClientStorage) {
	if initialSize <= 0 {
		initialSize = 0
	}
	storage = &ClientStorage{
		m:    make(map[uint32]*Client, initialSize),
		mseq: make([]*Client, 0, initialSize),
	}
	return
}

func (storage *ClientStorage) put(sessionId uint32, client *Client) {
	storage.m[sessionId] = client
	storage.mseq = append(storage.mseq, client)
	return
}

func (storage *ClientStorage) Put(sessionId uint32, client *Client) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.put(sessionId, client)
	return
}

func (storage *ClientStorage) get(sessionId uint32) (client *Client, ok bool) {
	client, ok = storage.m[sessionId]
	return
}

func (storage *ClientStorage) Has(sessionId uint32) (exists bool) {
	storage.mu.RLock()
	defer storage.mu.RUnlock()
	_, exists = storage.get(sessionId)
	return
}

func (storage *ClientStorage) Get(sessionId uint32) (client *Client, ok bool) {
	storage.mu.RLock()
	defer storage.mu.RUnlock()
	client, ok = storage.get(sessionId)
	return
}

func (storage *ClientStorage) delete(sessionId uint32) {
	ptr, exists := storage.get(sessionId)
	if !exists {
		return
	}
	delete(storage.m, sessionId)

	for i := 0; i < len(storage.mseq); i++ {
		if storage.mseq[i] == ptr {
			storage.mseq[i] = storage.mseq[len(storage.mseq)-1]
			storage.mseq[len(storage.mseq)-1] = nil
			storage.mseq = storage.mseq[:len(storage.mseq)-1]
			break
		}
	}

	return
}

func (storage *ClientStorage) Delete(sessionId uint32) {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	storage.delete(sessionId)
	return
}

func (storage *ClientStorage) len() int {
	return len(storage.mseq)
}

func (storage *ClientStorage) Len() int {
	storage.mu.RLock()
	defer storage.mu.RUnlock()
	return storage.len()
}

func (storage *ClientStorage) snapshotMap(f func(sessionId uint32, client *Client) bool, estimatedSizeFactor float64) (snap map[uint32]*Client) {
	if estimatedSizeFactor <= 0 || estimatedSizeFactor > 1 {
		estimatedSizeFactor = 1
	}

	length := storage.len()
	estimatedSize := int(math.Ceil(float64(length) * estimatedSizeFactor))

	snap = make(map[uint32]*Client, estimatedSize)

	for sId := 0; sId < length; sId++ {
		client := storage.mseq[sId]
		if !f(client.Session(), client) {
			continue
		}

		snap[client.Session()] = client
	}

	return
}

func (storage *ClientStorage) SnapshotMapWithFilter(f func(sessionId uint32, client *Client) bool, estimatedSizeFactor float64) (snap map[uint32]*Client) {
	storage.mu.RLock()
	defer storage.mu.RUnlock()
	return storage.snapshotMap(f, estimatedSizeFactor)
}

func (storage *ClientStorage) SnapshotMap() map[uint32]*Client {
	return storage.SnapshotMapWithFilter(func(sId uint32, c *Client) bool { return true }, 1)
}

func (storage *ClientStorage) snapshot(f func(sessionId uint32, client *Client) bool, estimatedSizeFactor float64) (snap []*Client) {
	if estimatedSizeFactor <= 0 || estimatedSizeFactor > 1 {
		estimatedSizeFactor = 1
	}

	length := storage.len()
	estimatedSize := int(math.Ceil(float64(length) * estimatedSizeFactor))

	snap = make([]*Client, 0, estimatedSize)

	for sId := 0; sId < length; sId++ {
		client := storage.mseq[sId]
		if !f(client.Session(), client) {
			continue
		}

		snap = append(snap, client)
	}

	return
}

func (storage *ClientStorage) SnapshotWithFilter(f func(sessionId uint32, client *Client) bool, estimatedSizeFactor float64) []*Client {
	storage.mu.RLock()
	defer storage.mu.RUnlock()
	return storage.snapshot(f, estimatedSizeFactor)
}

func (storage *ClientStorage) Snapshot() []*Client {
	return storage.SnapshotWithFilter(func(sId uint32, c *Client) bool { return true }, 1)
}
