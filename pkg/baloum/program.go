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

	"golang.org/x/exp/slices"

	"github.com/cilium/ebpf/asm"
)

type stackMemBlock struct {
	addr  int16
	size  int16
	inuse bool
}

type Program struct {
	insts asm.Instructions
}

type EditorInst = func() (asm.Instructions, error)

type VariableType int

const (
	Int8Type VariableType = iota
	Uint8Type
	Int16Type
	Uint16Type
	Int32Type
	Uint32Type
	Int64Type
	UInt64Type
	PtrType
)

func (vr VariableType) Sizeof() asm.Size {
	switch vr {
	case Int8Type, Uint8Type:
		return asm.Byte
	case Int16Type, Uint16Type:
		return asm.Half
	case Int32Type, Uint32Type:
		return asm.Word
	case Int64Type, UInt64Type:
		return asm.DWord
	case PtrType:
		return asm.DWord
	}
	return asm.InvalidSize
}

type Variable struct {
	Type VariableType
	Addr int16
}

func (vr Variable) Sizeof() asm.Size {
	return vr.Type.Sizeof()
}

type ProgramEditor struct {
	program *Program
	opts    ProgramEditorOpts
	insts   []EditorInst
	blocks  []stackMemBlock
	vars    map[string]Variable
}

func (p *Program) Prepare(instLimit int) error {
	if err := p.ResolveReferences(); err != nil {
		return err
	}

	if err := p.VerifyDag(); err != nil {
		return err
	}

	if len(p.insts) > instLimit {
		return errors.New("instruction limit reached")
	}

	return nil
}

func (p *Program) VerifyDag() error {
	var offsets []int

	for i := 0; i != len(p.insts); i++ {
		inst := p.insts[i]

		if slices.Contains(offsets, i) {
			return fmt.Errorf("not a dag, inst #%d: %v", i, inst)
		}
		offsets = append(offsets, i)

		if inst.OpCode == asm.Ja.Op(asm.ImmSource) {
			i += int(inst.Offset)
		}
	}

	return nil
}

func (p *Program) ResolveReferences() error {
	symbols := make(map[string]int)

	for offset, ins := range p.insts {
		if symbol := ins.Symbol(); symbol != "" {
			symbols[symbol] = offset
		}
	}

	for i, ins := range p.insts {
		if ref := ins.Reference(); ref != "" {
			offset, exists := symbols[ref]
			if exists {
				var inc int

				// correct with size of instruction size
				delta := offset - i - 1
				if delta > 0 {
					for j := 0; j != delta; j++ {
						if p.insts[i+j].Size() > 8 {
							inc++
						}
					}
				} else {
					for j := 0; j != delta; j-- {
						if p.insts[i+j].Size() > 8 {
							inc--
						}
					}
				}

				ins.Offset = int16(delta + inc)
				p.insts[i] = ins
			}
		}
	}

	return nil
}

type ProgramEditorOpts struct {
	StackSize int
}

func (p *ProgramEditorOpts) applyDefault() {
	if p.StackSize == 0 {
		p.StackSize = DEFAULT_STACK_SIZE
	}
}

func (p *Program) Edit(opts ProgramEditorOpts) *ProgramEditor {
	opts.applyDefault()

	return &ProgramEditor{
		program: p,
		opts:    opts,
		vars:    make(map[string]Variable),
	}
}

func (p *ProgramEditor) Commit() error {
	for _, inst := range p.insts {
		insts, err := inst()
		if err != nil {
			return err
		}

		p.program.insts = append(p.program.insts, insts...)
	}
	return nil
}

func (p *ProgramEditor) StackAlloc(size int16) (int16, error) {
	var lastAddr int16
	for i, block := range p.blocks {
		if !block.inuse && block.size >= size {
			left := make([]stackMemBlock, i)
			right := make([]stackMemBlock, len(p.blocks)-i-1)

			copy(left, p.blocks[0:i])
			copy(right, p.blocks[i+1:])

			// fragment
			inuse := stackMemBlock{
				addr:  lastAddr - int16(size),
				size:  size,
				inuse: true,
			}
			p.blocks = append(left, inuse)

			if block.size > size {
				size = block.size - size
				free := stackMemBlock{
					addr: inuse.addr - int16(size),
					size: size,
				}

				p.blocks = append(p.blocks, free)
			}
			p.blocks = append(p.blocks, right...)

			return inuse.addr, nil
		}
		lastAddr = block.addr
	}

	if lastAddr-int16(size) < -DEFAULT_STACK_SIZE {
		return 0, errors.New("out of stack memory")
	}

	block := stackMemBlock{
		addr:  lastAddr - int16(size),
		size:  size,
		inuse: true,
	}
	p.blocks = append(p.blocks, block)

	return block.addr, nil
}

func (p *ProgramEditor) Sizeof(addr int16) asm.Size {
	for _, block := range p.blocks {
		if block.addr == addr {
			switch block.size {
			case 1:
				return asm.Byte
			case 2:
				return asm.Half
			case 4:
				return asm.Word
			case 8:
				return asm.DWord
			}
		}
	}
	return asm.InvalidSize
}

func (p *ProgramEditor) StackFree(addr int16) {
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

func (p *ProgramEditor) stackBytes(bytes []byte) (int16, asm.Instructions, error) {
	var instructions asm.Instructions

	var (
		values []int64
		value  int64
		size   int16
		chars  []int64
	)

	for _, c := range bytes {
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
		return 0, nil, err
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

	return addr, instructions, nil
}

func (p *ProgramEditor) Return(code int) {
	inst := func() (asm.Instructions, error) {
		var instructions asm.Instructions
		instructions = append(instructions,
			asm.Mov.Imm(asm.R0, int32(code)),
			asm.Return(),
		)

		return instructions, nil
	}
	p.insts = append(p.insts, inst)
}

func (p *ProgramEditor) Printk(format string, arg1 interface{}, arg2 interface{}, arg3 interface{}) {
	inst := func() (asm.Instructions, error) {
		var instructions asm.Instructions

		// format
		addr, insts, err := p.stackBytes([]byte(format))
		if err != nil {
			return nil, err
		}
		instructions = append(instructions, insts...)

		instructions = append(instructions,
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, int32(addr)),
			asm.Mov.Imm(asm.R2, int32(len(format)+1)),
		)

		// add arg using the type, either the direct value of doing a var resolution
		addArg := func(reg asm.Register, arg interface{}) error {
			switch arg := arg.(type) {
			case int32:
				instructions = append(instructions, asm.Mov.Imm(reg, int32(arg)))
			case string:
				vr, exists := p.vars[arg]
				if !exists {
					return fmt.Errorf("variable %s doesn't exist", arg)
				}
				instructions = append(
					instructions,
					asm.LoadMem(reg, asm.RFP, vr.Addr, vr.Sizeof()),
				)
			case nil:
			default:
				return fmt.Errorf("unknown argument type %d", arg1)
			}

			return nil
		}

		if err := addArg(asm.R3, arg1); err != nil {
			return nil, err
		}
		if err := addArg(asm.R4, arg2); err != nil {
			return nil, err
		}
		if err := addArg(asm.R5, arg3); err != nil {
			return nil, err
		}

		instructions = append(instructions,
			asm.FnTracePrintk.Call(),
		)

		p.StackFree(addr)

		return instructions, nil
	}
	p.insts = append(p.insts, inst)
}

func (p *ProgramEditor) NewVar(name string, value interface{}) {
	inst := func() (asm.Instructions, error) {
		var instructions asm.Instructions

		switch v := value.(type) {
		case int8:
		case uint8:
		case int16:
		case uint16:
		case int32:
		case uint32:
			addr, err := p.StackAlloc(int16(asm.Word.Sizeof()))
			if err != nil {
				return nil, err
			}
			p.vars[name] = Variable{Type: Uint32Type, Addr: addr}

			instructions = append(instructions,
				asm.Mov.Imm(asm.R1, int32(v)),
				asm.StoreMem(asm.RFP, addr, asm.R1, asm.Word),
			)
		case int64:
		case uint64:
		case []byte:
			ptr, err := p.StackAlloc(int16(asm.DWord.Sizeof()))
			if err != nil {
				return nil, err
			}
			p.vars[name] = Variable{Type: PtrType, Addr: ptr}

			addr, insts, err := p.stackBytes(v)
			if err != nil {
				return nil, err
			}
			instructions = append(instructions, insts...)

			instructions = append(instructions,
				asm.Mov.Imm(asm.R1, int32(p.opts.StackSize+int(addr))),
				asm.StoreMem(asm.RFP, ptr, asm.R1, asm.DWord),
			)
		case string:
			ptr, err := p.StackAlloc(int16(asm.DWord.Sizeof()))
			if err != nil {
				return nil, err
			}
			p.vars[name] = Variable{Type: PtrType, Addr: ptr}

			addr, insts, err := p.stackBytes([]byte(v))
			if err != nil {
				return nil, err
			}
			instructions = append(instructions, insts...)

			instructions = append(instructions,
				asm.Mov.Imm(asm.R1, int32(p.opts.StackSize+int(addr))),
				asm.StoreMem(asm.RFP, ptr, asm.R1, asm.DWord),
			)
		}

		return instructions, nil
	}
	p.insts = append(p.insts, inst)
}

func (p *ProgramEditor) FreeVar() {
	// TODO(safchain) think of ptr
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
