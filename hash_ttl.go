package main

import (
	"sync"
	"time"
)

//Value represents map value.
type Value interface{}

// HashTTL is a string to value map with time to live keys
// and concurrency support.
type HashTTL struct {
	data  map[string]Value
	times map[string]int64
	ttl   int64
	mutex *sync.Mutex
}

// NewHashTTL returns a pointer to instance of HashTTL with set time to live.
func NewHashTTL(ttl int64) *HashTTL {
	return &HashTTL{data: make(map[string]Value),
		times: make(map[string]int64),
		ttl:   ttl,
		mutex: &sync.Mutex{}}
}

// Get returns value by key if it is present in the map and ttl
// hasn't run out.
func (h *HashTTL) Get(key string) (Value, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	entryTime, present := h.times[key]
	if !present {
		return nil, false
	}
	curTime := time.Now().Unix()
	if curTime-entryTime > h.ttl {
		delete(h.data, key)
		delete(h.times, key)
		return nil, false
	}
	return h.data[key], true
}

//Set sets key in the map with preset ttl.
func (h *HashTTL) Set(key string, val Value) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.data[key] = val
	h.times[key] = time.Now().Unix()
}
