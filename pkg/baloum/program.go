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
	"math"

	"github.com/cilium/ebpf/asm"
)

func ResolveReferences(insts asm.Instructions) error {
	symbols := make(map[string]int)

	for offset, ins := range insts {
		if symbol := ins.Symbol(); symbol != "" {
			symbols[symbol] = offset
		}
	}

	for i, ins := range insts {
		if ref := ins.Reference(); ref != "" {
			offset, exists := symbols[ref]
			if exists {
				delta := offset - i - 1
				if delta < 0 {
					return fmt.Errorf("backward branch ins %d : %v", i, ins)
				}
				// correct with size of instruction size
				var inc int
				for j := 0; j != delta; j++ {
					if insts[i+j].Size() > 8 {
						inc++
					}
				}
				ins.Offset = int16(delta + inc)
				insts[i] = ins
			}
		}
	}

	return nil
}

type stackMemBlock struct {
	addr  int16
	size  int16
	inuse bool
}

type Program struct {
	insts     asm.Instructions
	blocks    []stackMemBlock
	allocated int16
}

func (p *Program) StackAlloc(size int16) (int16, error) {
	var lastAddr int16
	for i, block := range p.blocks {
		if !block.inuse && block.size >= size {
			left := make([]stackMemBlock, i)
			right := make([]stackMemBlock, len(p.blocks)-i-1)

			copy(left, p.blocks[0:i])
			copy(right, p.blocks[i+1:])

			// fragment
			inuse := stackMemBlock{
				addr:  lastAddr - size,
				size:  size,
				inuse: true,
			}
			p.blocks = append(left, inuse)

			if block.size > size {
				size = block.size - size
				free := stackMemBlock{
					addr: inuse.addr - size,
					size: size,
				}

				p.blocks = append(p.blocks, free)
			}
			p.blocks = append(p.blocks, right...)

			p.allocated += size
			return inuse.addr, nil
		}
		lastAddr = block.addr
	}

	if lastAddr-size < -DEFAULT_STACK_SIZE {
		return 0, errors.New("out of stack memory")
	}

	block := stackMemBlock{
		addr:  lastAddr - size,
		size:  size,
		inuse: true,
	}
	p.blocks = append(p.blocks, block)

	return block.addr, nil
}

func (p *Program) StackFree(addr int16) {
	for i, block := range p.blocks {
		if block.addr == addr {
			if i+1 == len(p.blocks) {
				// last block, remove it
				p.blocks = p.blocks[0:i]
			} else {
				block := p.blocks[i]
				block.inuse = false

				p.blocks[i] = block
			}
		}
	}
}

type Printk struct {
	addr         int16
	instructions asm.Instructions
}

func (p *Program) NewPrintk(format string) (*Printk, error) {
	var instructions asm.Instructions

	var values []int64
	var value int64
	var size int16

	var chars []int64
	for _, c := range format {
		chars = append(chars, int64(c))
	}
	chars = append(chars, 0) // 0

	for _, c := range chars {
		value = value | c<<(size*8)
		size++

		if size == 8 {
			values = append(values, value)
			value, size = 0, 0
		}
	}

	if size != 0 {
		values = append(values, value)
	}

	addr, err := p.StackAlloc(int16(len(values) * 8))
	if err != nil {
		return nil, err
	}

	ptr := addr
	for _, value := range values {
		switch {
		case value <= math.MaxUint16:
			instructions = append(instructions,
				asm.Mov.Imm(asm.R1, int32(value)),
				asm.StoreMem(asm.RFP, ptr, asm.R1, asm.Half),
			)
		case value <= math.MaxUint32:
			instructions = append(instructions,
				asm.Mov.Imm(asm.R1, int32(value)),
				asm.StoreMem(asm.RFP, ptr, asm.R1, asm.Word),
			)
		default:
			instructions = append(instructions,
				asm.LoadImm(asm.R1, value, asm.DWord),
				asm.StoreMem(asm.RFP, ptr, asm.R1, asm.DWord),
			)
		}
		ptr += 8
	}

	// TODO add reg backup/restore

	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(addr)),
		asm.Mov.Imm(asm.R2, int32(len(format)+1)),
		asm.FnTracePrintk.Call(),
	)

	return &Printk{
		addr:         addr,
		instructions: instructions,
	}, nil
}

func (p Printk) Call() asm.Instructions {
	return p.instructions
}

func (p *Program) Append(insts ...interface{}) {
	p.insts = append(p.insts, Instructions(insts...)...)
}

func (p *Program) Instructions() asm.Instructions {
	return p.insts
}

func Instructions(insts ...interface{}) asm.Instructions {
	var instructions asm.Instructions
	for _, inst := range insts {
		switch t := inst.(type) {
		case asm.Instruction:
			instructions = append(instructions, t)
		case []asm.Instruction:
			instructions = append(instructions, t...)
		case asm.Instructions:
			instructions = append(instructions, t...)
		}
	}
	return instructions
}
