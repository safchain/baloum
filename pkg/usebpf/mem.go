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

package usebpf

import (
	"container/list"
	"errors"
)

const (
	// Memory scheme
	// heap mask  				0xff00000000000000
	// heap block idx  			0x00ffff0000000000
	// unused  					0x000000ff00000000
	// heap block/stack addr  	0x00000000ffffffff

	// HEAP_ADDR_MASK identifying heap address
	HEAP_ADDR_MASK uint64 = 0xff00000000000000
	// ADDR_MASK
	ADDR_MASK uint64 = 0xffffffff
	// IDX_MASK
	IDX_MASK uint64 = 0xffff
)

type MemBlock struct {
	idx  uint32
	data []byte
}

type Heap struct {
	idx    uint32
	blocks *list.List
}

func NewHeap() *Heap {
	return &Heap{
		blocks: list.New(),
	}
}

func (h *Heap) GetMem(addr uint64) ([]byte, uint64, error) {
	idx := addr >> (5 * 8) & IDX_MASK
	for el := h.blocks.Front(); el != nil; el = el.Next() {
		block := el.Value.(MemBlock)
		if block.idx == uint32(idx) {
			return block.data, addr & ADDR_MASK, nil
		}
	}

	return nil, 0, errors.New("address not found")
}

func (h *Heap) Alloc(size int) uint64 {
	return h.AllocWith(make([]byte, size))
}

func (h *Heap) Free(addr uint64) {
	idx := addr >> (5 * 8) & IDX_MASK
	for el := h.blocks.Front(); el != nil; el = el.Next() {
		if el.Value.(MemBlock).idx == uint32(idx) {
			h.blocks.Remove(el)
			break
		}
	}
}

func (h *Heap) AllocWith(data []byte) uint64 {
	idx := h.idx
	h.blocks.PushBack(MemBlock{idx: idx, data: data})
	h.idx++
	return blockIdxToAddr(idx)
}

func blockIdxToAddr(idx uint32) uint64 {
	return HEAP_ADDR_MASK | (uint64(idx)&0xffff)<<(5*8)
}
