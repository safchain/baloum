/*
Copyright © 2022 SYLVAIN AFCHAIN

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package baloum

import (
	"errors"

	lru "github.com/hashicorp/golang-lru"
)

type MapLRUStorage struct {
	heap       *Heap
	maxEntries uint32
	flags      uint32
	data       *lru.Cache
}

func (m *MapLRUStorage) Lookup(key []byte) (uint64, error) {
	entry, exists := m.data.Get(string(key))
	if !exists {
		return 0, nil
	}
	return entry.(uint64), nil
}

func (m *MapLRUStorage) Update(key []byte, value []byte, kind MapUpdateType) (bool, error) {
	addr, exists := m.data.Get(string(key))
	if exists {
		if kind == BPF_NOEXIST {
			return false, nil
		}
		m.heap.Free(addr.(uint64))
	}
	m.data.Add(string(key), m.heap.AllocWith(value))

	return true, nil
}

func (m *MapLRUStorage) Delete(key []byte) (bool, error) {
	addr, exists := m.data.Get(string(key))
	if exists {
		m.heap.Free(addr.(uint64))
	}
	return m.data.Remove(string(key)), nil
}

func (m *MapLRUStorage) Keys() ([][]byte, error) {
	var keys [][]byte

	for _, key := range m.data.Keys() {
		keys = append(keys, key.([]byte))
	}

	return keys, nil
}

func (m *MapLRUStorage) Read() (<-chan []byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapLRUStorage) Write(data []byte) error {
	return errors.New("operation not supported")
}

func NewMapLRUStorage(id int, heap *Heap, keySize, valueSize, maxEntries, flags uint32) (MapStorage, error) {
	cache, err := lru.NewWithEvict(int(maxEntries), func(key, value interface{}) {
		heap.Free(value.(uint64))
	})
	if err != nil {
		return nil, err
	}

	return &MapLRUStorage{
		heap:       heap,
		maxEntries: maxEntries,
		data:       cache,
	}, nil
}
