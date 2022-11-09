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

import "errors"

type MapHashStorage struct {
	heap       *Heap
	maxEntries uint32
	flags      uint32
	data       map[string]uint64
}

func (m *MapHashStorage) Lookup(key []byte) (uint64, error) {
	return m.data[string(key)], nil
}

func (m *MapHashStorage) Update(key []byte, value []byte, kind MapUpdateType) (bool, error) {
	if len(m.data) >= int(m.maxEntries) {
		return false, nil
	}

	addr, exists := m.data[string(key)]
	if exists {
		if kind == BPF_NOEXIST {
			return false, nil
		}
		m.heap.Free(addr)
	}
	m.data[string(key)] = m.heap.AllocWith(value)

	return true, nil
}

func (m *MapHashStorage) Delete(key []byte) (bool, error) {
	if addr, exists := m.data[string(key)]; exists {
		m.heap.Free(addr)
		delete(m.data, string(key))
		return true, nil
	}
	return false, nil
}

func (m *MapHashStorage) Keys() ([][]byte, error) {
	var keys [][]byte

	for key := range m.data {
		keys = append(keys, []byte(key))
	}

	return keys, nil
}

func (m *MapHashStorage) Read() (<-chan []byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapHashStorage) Write(data []byte) error {
	return errors.New("operation not supported")
}

func NewMapHashStorage(id int, heap *Heap, keySize, valueSize, maxEntries, flags uint32) (MapStorage, error) {
	return &MapHashStorage{
		heap:       heap,
		maxEntries: maxEntries,
		data:       make(map[string]uint64),
	}, nil
}
