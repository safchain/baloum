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
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type MapUpdateType int

const (
	BPF_ANY MapUpdateType = iota
	BPF_NOEXIST
	BPF_EXIST
	BPF_F_LOCK
)

type MapStorage interface {
	Lookup(key []byte) (uint64, error)
	Update(key []byte, value []byte, kind MapUpdateType) (bool, error)
	Delete(key []byte) (bool, error)
	Keys() ([][]byte, error)
	Read() (<-chan []byte, error)
	Write(data []byte) error
}

type Map struct {
	vm        *VM
	id        int
	keySize   uint32
	valueSize uint32
	storage   MapStorage
}

func (m *Map) LookupAddr(key interface{}) (uint64, error) {
	b, err := ToBytes(key, int(m.keySize))
	if err != nil {
		return 0, err
	}

	return m.storage.Lookup(b)
}

func (m *Map) Lookup(key interface{}) ([]byte, error) {
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

func (m *Map) Update(key interface{}, value interface{}, kind MapUpdateType) (bool, error) {
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

func (m *Map) Delete(key interface{}) (bool, error) {
	b, err := ToBytes(key, int(m.keySize))
	if err != nil {
		return false, err
	}

	return m.storage.Delete(b)
}

func (m *Map) Read() (<-chan []byte, error) {
	return m.storage.Read()
}

func (m *Map) Write(data interface{}, size uint64) error {
	b, err := ToBytes(data, int(size))
	if err != nil {
		return err
	}

	return m.storage.Write(b)
}

func (m *Map) Keys() ([][]byte, error) {
	return m.storage.Keys()
}

func (m *Map) KeySize() uint32 {
	return m.keySize
}

func (m *Map) ValueSize() uint32 {
	return m.valueSize
}

func (m *Map) ID() int {
	return m.id
}

type MapCollection struct {
	vm        *VM
	mapByName map[string]*Map
	mapById   []*Map
}

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
			id:        len(mc.mapById),
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
		default:
			return fmt.Errorf("map type %s not supported", m.Type)
		}

		mc.mapByName[m.Name] = _map
		mc.mapById = append(mc.mapById, _map)
	}

	return nil
}

func (mc *MapCollection) GetMapById(id int) *Map {
	if mc == nil {
		return nil
	}

	if id >= len(mc.mapById) {
		return nil
	}

	return mc.mapById[id]
}

func (mc *MapCollection) GetMapByName(name string) *Map {
	if mc == nil {
		return nil
	}

	return mc.mapByName[name]
}

func (mc *MapCollection) LoadMaps(spec *ebpf.CollectionSpec, sections ...string) error {
	for _, prog := range spec.Programs {
		if !progMatch(prog, sections...) {
			continue
		}

		for _, inst := range prog.Instructions {
			if inst.Src == asm.PseudoMapFD || inst.Dst == asm.PseudoMapFD {
				if err := mc.LoadMap(spec, inst.Reference()); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func NewMapCollection(vm *VM) *MapCollection {
	return &MapCollection{
		vm:        vm,
		mapByName: make(map[string]*Map),
	}
}
