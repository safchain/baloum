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
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// MapUpdateType is the type for the map update type
type MapUpdateType int

const (
	// BPF_ANY is the type for the map update type
	BPF_ANY MapUpdateType = iota
	// BPF_NOEXIST is the type for the map update type
	BPF_NOEXIST
	// BPF_EXIST is the type for the map update type
	BPF_EXIST
	// BPF_F_LOCK is the type for the map update type
)

// MapStorage is the type for the map storage
type MapStorage interface {
	// Lookup looks up a key in the map
	Lookup(key []byte) (uint64, error)
	// Update updates a key in the map
	Update(key []byte, value []byte, kind MapUpdateType) (bool, error)
	// Delete deletes a key in the map
	Delete(key []byte) (bool, error)
	// Keys returns the keys of the map
	Keys() ([][]byte, error)
	// Read reads the map
	Read() (<-chan []byte, error)
	// Write writes to the map
	Write(data []byte) error
}

// Map is the type for the map
type Map struct {
	vm        *VM
	fd        int
	keySize   uint32
	valueSize uint32
	storage   MapStorage
}

// LookupAddr looks up a key in the map
func (m *Map) LookupAddr(key interface{}) (uint64, error) {
	b, err := ToBytes(key, int(m.keySize))
	if err != nil {
		return 0, err
	}

	return m.storage.Lookup(b)
}

func (m *Map) LookupBytes(key interface{}) ([]byte, error) {
	addr, err := m.LookupAddr(key)
	if addr == 0 || err != nil {
		return nil, err
	}

	bytes, addr, err := m.vm.heap.GetMem(addr)
	if err != nil {
		return nil, err
	}

	return bytes[addr:], nil
}

// Lookup looks up a key in the map
func (m *Map) Lookup(key interface{}, value interface{}) error {
	if m == nil {
		return errors.New("nil map")
	}

	data, err := m.LookupBytes(key)
	if err != nil {
		return err
	}

	return FromBytes(data, value)
}

// Update updates a key in the map
func (m *Map) Update(key interface{}, value interface{}, kind MapUpdateType) (bool, error) {
	if m == nil {
		return false, errors.New("nil map")
	}

	bKey, err := ToBytes(key, int(m.keySize))
	if err != nil {
		return false, err
	}

	bValue, err := ToBytes(value, int(m.valueSize))
	if err != nil {
		return false, err
	}

	return m.storage.Update(bKey, bValue, kind)
}

// Delete deletes a key in the map
func (m *Map) Delete(key interface{}) (bool, error) {
	if m == nil {
		return false, errors.New("nil map")
	}

	b, err := ToBytes(key, int(m.keySize))
	if err != nil {
		return false, err
	}

	return m.storage.Delete(b)
}

func (m *Map) Read() (<-chan []byte, error) {
	return m.storage.Read()
}

// Write writes to the map
func (m *Map) Write(data interface{}, size uint64) error {
	b, err := ToBytes(data, int(size))
	if err != nil {
		return err
	}

	return m.storage.Write(b)
}

// Keys returns the keys of the map
func (m *Map) Keys() ([][]byte, error) {
	return m.storage.Keys()
}

// KeySize returns the key size of the map
func (m *Map) KeySize() uint32 {
	return m.keySize
}

// ValueSize returns the value size of the map
func (m *Map) ValueSize() uint32 {
	return m.valueSize
}

// FD returns the file descriptor of the map
func (m *Map) FD() int {
	return m.fd
}

// Iterator returns an iterator for the map
func (m *Map) Iterator() (*MapIterator, error) {
	keys, err := m.Keys()
	if err != nil {
		return nil, err
	}
	return &MapIterator{
		_map: m,
		keys: keys,
	}, nil
}

// MapIterator is the type for the map iterator
type MapIterator struct {
	_map *Map
	keys [][]byte
	idx  int
}

// Next returns the next key and value in the map
func (mi *MapIterator) Next() ([]byte, []byte, bool) {
	if mi.idx >= len(mi.keys) {
		return nil, nil, false
	}
	key := mi.keys[mi.idx]

	value, err := mi._map.LookupBytes(key)
	if err != nil {
		return nil, nil, false
	}
	mi.idx++
	return key, value, true
}

// MapCollection is the type for the map collection
type MapCollection struct {
	vm        *VM
	mapByName map[string]*Map
	mapByFd   []*Map
}

// LoadMap loads a map by name
func (mc *MapCollection) LoadMap(spec *ebpf.CollectionSpec, name string) error {
	if _, exists := mc.mapByName[name]; exists {
		return nil
	}

	for _, m := range spec.Maps {
		if m.Name != name {
			continue
		}

		var err error
		_map := &Map{
			fd:        len(mc.mapByFd),
			vm:        mc.vm,
			keySize:   m.KeySize,
			valueSize: m.ValueSize,
		}

		switch m.Type {
		case ebpf.Array:
			_map.storage, err = NewMapArrayStorage(mc.vm, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
			if err != nil {
				return err
			}
		case ebpf.Hash:
			_map.storage, err = NewMapHashStorage(mc.vm, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
			if err != nil {
				return err
			}
		case ebpf.LRUHash:
			_map.storage, err = NewMapLRUStorage(mc.vm, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
			if err != nil {
				return err
			}
		case ebpf.PerfEventArray:
			_map.storage, err = NewMapPerfStorage(mc.vm, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
			if err != nil {
				return err
			}
		case ebpf.PerCPUArray:
			_map.storage, err = NewMapPerCPUArrayStorage(mc.vm, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
			if err != nil {
				return err
			}
		case ebpf.ProgramArray:
			_map.storage, err = NewMapProgArrayStorage(mc.vm, m.KeySize, m.ValueSize, m.MaxEntries, m.Flags)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("map type %s not supported", m.Type)
		}

		mc.mapByName[m.Name] = _map
		mc.mapByFd = append(mc.mapByFd, _map)
	}

	return nil
}

// GetMapById returns a map by id
func (mc *MapCollection) GetMapByFd(fd int) *Map {
	if mc == nil {
		return nil
	}

	if fd >= len(mc.mapByFd) {
		return nil
	}

	return mc.mapByFd[fd]
}

// GetMapByName returns a map by name
func (mc *MapCollection) GetMapByName(name string) *Map {
	if mc == nil {
		return nil
	}

	return mc.mapByName[name]
}

// LoadMaps loads multiple maps by name
func (mc *MapCollection) LoadMaps(spec *ebpf.CollectionSpec, sections ...string) error {
	for _, prog := range spec.Programs {
		if !progMatch(prog, sections...) {
			continue
		}

		for _, inst := range prog.Instructions {
			ref := inst.Reference()
			if ref == "" {
				continue
			}
			if inst.Src != asm.PseudoMapFD && inst.Dst != asm.PseudoMapFD {
				continue
			}
			if err := mc.LoadMap(spec, ref); err != nil {
				return err
			}
		}
	}

	return nil
}

// NewMapCollection creates a new map collection
func NewMapCollection(vm *VM) *MapCollection {
	return &MapCollection{
		vm:        vm,
		mapByName: make(map[string]*Map),
	}
}
