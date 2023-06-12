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
)

type MapPerCPUArrayStorage struct {
	vm         *VM
	maxEntries uint32

	data map[uint32][]uint64
}

func (m *MapPerCPUArrayStorage) getCPU() (uint32, error) {
	var cpu uint32
	if m.vm.Opts.Fncs.GetSmpProcessorId != nil {
		id, err := m.vm.Opts.Fncs.GetSmpProcessorId(m.vm)
		if err != nil {
			return 0, err
		}
		cpu = uint32(id)
	}

	if int(cpu) >= len(m.data) {
		return 0, errors.New("out of bound")
	}

	return cpu, nil
}

func (m *MapPerCPUArrayStorage) Lookup(key []byte) (uint64, error) {
	cpu, err := m.getCPU()
	if err != nil {
		return 0, err
	}

	if int(cpu) > len(m.data) {
		return 0, errors.New("out of bound")
	}

	idx, err := mapArrayKeyIndex(key)
	if err != nil {
		return 0, err
	}

	if idx > len(m.data[cpu]) {
		return 0, errors.New("out of bound")
	}

	return m.data[cpu][idx], nil
}

func (m *MapPerCPUArrayStorage) Update(key []byte, value []byte, kind MapUpdateType) (bool, error) {
	idx, err := mapArrayKeyIndex(key)
	if err != nil {
		return false, err
	}

	if idx > len(m.data) {
		return false, errors.New("out of bound")
	}

	cpu, err := m.getCPU()
	if err != nil {
		return false, err
	}

	m.vm.heap.Free(m.data[cpu][idx])
	m.data[cpu][idx] = m.vm.heap.AllocWith(value)

	return true, nil
}

func (m *MapPerCPUArrayStorage) Delete(key []byte) (bool, error) {
	return false, errors.New("operation not supported")
}

func (m *MapPerCPUArrayStorage) Keys() ([][]byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapPerCPUArrayStorage) Read() (<-chan []byte, error) {
	return nil, errors.New("operation not supported")
}

func (m *MapPerCPUArrayStorage) Write(data []byte) error {
	return errors.New("operation not supported")
}

func NewMapPerCPUArrayStorage(vm *VM, keySize, valueSize, maxEntries, flags uint32) (MapStorage, error) {
	data := make(map[uint32][]uint64, maxEntries)
	for cpu := uint32(0); cpu != uint32(vm.Opts.CPUs); cpu++ {
		entries := make([]uint64, maxEntries)
		data[cpu] = entries

		for i := range entries {
			entries[i] = vm.heap.Alloc(int(valueSize))
		}
	}

	return &MapPerCPUArrayStorage{
		vm:         vm,
		maxEntries: maxEntries,
		data:       data,
	}, nil
}
