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
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/cilium/ebpf/asm"
)

type SymbolType = string

const (
	JumpSymbolType       SymbolType = "-jmp"
	BreakpointSymbolType SymbolType = "breakpoint"
)

// see : https://docs.kernel.org/bpf/verifier.html?highlight=ebpf%20tc

type stackMemBlock struct {
	addr  int16
	size  int16
	inuse bool
}

type Program struct {
	insts asm.Instructions
}

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
	program   *Program
	opts      ProgramEditorOpts
	insts     asm.Instructions
	blocks    []stackMemBlock
	symbolIdx int
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
	}
}

func (p *ProgramEditor) Commit() {
	// relocate symbol
	for i := 0; i != len(p.insts); i++ {
		if symbol := p.insts[i].Symbol(); strings.HasSuffix(symbol, JumpSymbolType) {
			p.insts[i] = p.insts[i].WithSymbol("")
			p.insts[i+1] = p.insts[i+1].WithSymbol(symbol)
			i++
		}
	}

	p.program.insts = append(p.program.insts, p.insts...)

	for _, inst := range p.program.insts {
		fmt.Printf("%v [%s]\n", inst, inst.Symbol())
	}
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

	if lastAddr-int16(size) < -int16(p.opts.StackSize) {
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

func (p *ProgramEditor) nextSymbolSuffix(kind SymbolType) string {
	symbol := strconv.Itoa(p.symbolIdx) + string(kind)
	p.symbolIdx++
	return symbol
}

func (p *ProgramEditor) Return(code int) {
	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R0, int32(code)),
		asm.Return(),
	)
}

// TODO(safchain) make args optionals
func (p *ProgramEditor) Printk(format string, args ...interface{}) error {
	if len(args) > 3 {
		return errors.New("maximum of args excedeed")
	}

	// format
	addr, insts, err := p.stackBytes([]byte(format))
	if err != nil {
		return err
	}
	p.insts = append(p.insts, insts...)

	p.insts = append(p.insts,
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(addr)),
		asm.Mov.Imm(asm.R2, int32(len(format)+1)),
	)

	// add arg using the type, either the direct value of doing a var resolution
	addArg := func(reg asm.Register, arg interface{}) error {
		switch arg := arg.(type) {
		case int32:
			p.insts = append(p.insts, asm.Mov.Imm(reg, int32(arg)))
		case *Variable:
			switch arg.Type {
			case PtrType:
				p.insts = append(p.insts,
					asm.Mov.Reg(reg, asm.RFP),
					asm.Add.Imm(reg, int32(arg.Addr)),
				)
			default:
				p.insts = append(p.insts,
					asm.LoadMem(reg, asm.RFP, arg.Addr, arg.Sizeof()),
				)
			}
		case nil:
		default:
			return fmt.Errorf("unknown argument type %d", arg)
		}

		return nil
	}

	regs := []asm.Register{asm.R3, asm.R4, asm.R5}
	for i, arg := range args {
		if err := addArg(regs[i], arg); err != nil {
			return err
		}
	}

	p.insts = append(p.insts,
		asm.FnTracePrintk.Call(),
	)

	p.StackFree(addr)

	return nil
}

func (p *ProgramEditor) StrStaticCmp(var1 *Variable, str string) func(trueSym, falseSym string) error {
	return func(trueSym, falseSym string) error {
		if var1.Type != PtrType {
			return errors.New("invalid variable type")
		}

		size := int16(len(str))

		p.insts = append(p.insts,
			asm.Mov.Reg(asm.R1, asm.RFP),
			asm.Add.Imm(asm.R1, int32(var1.Addr)),
		)

		for i := int16(0); i != size; i++ {
			p.insts = append(p.insts,
				asm.LoadMem(asm.R2, asm.R1, i, asm.Byte),
				asm.JNE.Imm(asm.R2, int32(str[i]), falseSym),
			)
		}

		p.insts = append(p.insts,
			asm.LoadMem(asm.R2, asm.RFP, var1.Addr+size, asm.Byte),
			asm.JEq.Imm(asm.R2, 0, trueSym),
			asm.Ja.Label(falseSym),
		)

		return nil
	}
}

func (p *ProgramEditor) StrCmp(var1 *Variable, var2 *Variable, unroll int) func(trueSym, falseSym string) error {
	return func(trueSym string, falseSym string) error {
		if var1.Type != PtrType || var2.Type != PtrType {
			return errors.New("invalid variable type")
		}

		p.insts = append(p.insts,
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Mov.Reg(asm.R3, asm.RFP),
			asm.Add.Imm(asm.R2, int32(var1.Addr)),
			asm.Add.Imm(asm.R3, int32(var2.Addr)),
		)

		addr1, addr2 := var1.Addr, var2.Addr

		for i := 0; i != unroll; i++ {
			if addr1 == 0 || addr2 == 0 {
				break
			}

			p.insts = append(p.insts,
				asm.LoadMem(asm.R4, asm.R2, int16(i), asm.Byte),
				asm.LoadMem(asm.R5, asm.R3, int16(i), asm.Byte),
				asm.JNE.Reg(asm.R4, asm.R5, falseSym),
				asm.Or.Reg(asm.R4, asm.R5),
				asm.JEq.Imm(asm.R4, int32(0), trueSym),
			)
			addr1++
			addr2++
		}

		p.insts = append(p.insts,
			asm.Ja.Label(falseSym),
		)

		return nil
	}
}

func (p *ProgramEditor) True(trueSym, _ string) error {
	p.insts = append(p.insts,
		asm.Ja.Label(trueSym),
	)
	return nil
}

func (p *ProgramEditor) False(_, falseSym string) error {
	p.insts = append(p.insts,
		asm.Ja.Label(falseSym),
	)
	return nil
}

func (p *ProgramEditor) lastInstIdx() int {
	return len(p.insts) - 1
}

func (p *ProgramEditor) IfThenElse(cond func(trueSym, falseSym string) error, then func() error, els func() error) error {
	symSuffix := p.nextSymbolSuffix(JumpSymbolType)

	var (
		trueSym  = "then-" + symSuffix
		falseSym = "endif-" + symSuffix
	)

	if els != nil {
		falseSym = "endthen-" + symSuffix
	}

	if err := cond(trueSym, falseSym); err != nil {
		return err
	}

	p.insts[p.lastInstIdx()] = p.insts[p.lastInstIdx()].WithSymbol(trueSym)
	if err := then(); err != nil {
		return err
	}
	p.insts = append(p.insts,
		asm.Ja.Label("endif-"+symSuffix).WithSymbol("endthen-"+symSuffix),
	)

	if els != nil {
		if err := els(); err != nil {
			return err
		}
	}
	p.insts[p.lastInstIdx()] = p.insts[p.lastInstIdx()].WithSymbol("endif-" + symSuffix)

	return nil
}

func (p *ProgramEditor) NewNumberVar(kind VariableType, value int32) (*Variable, error) {
	addr, err := p.StackAlloc(int16(asm.Word.Sizeof()))
	if err != nil {
		return nil, err
	}
	variable := &Variable{Type: kind, Addr: addr}

	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R1, value),
		asm.StoreMem(asm.RFP, addr, asm.R1, asm.Word),
	)

	return variable, nil
}

func (p *ProgramEditor) NewByteArrayVar(value []byte) (*Variable, error) {
	addr, insts, err := p.stackBytes(value)
	if err != nil {
		return nil, err
	}
	variable := &Variable{Type: PtrType, Addr: addr}
	//p.vars[name] = variable

	p.insts = append(p.insts, insts...)

	return variable, nil
}

func (p *ProgramEditor) NewVar(value interface{}) (*Variable, error) {
	switch v := value.(type) {
	case int8:
		return p.NewNumberVar(Int8Type, int32(v))
	case uint8:
		return p.NewNumberVar(Uint8Type, int32(v))
	case int16:
		return p.NewNumberVar(Int16Type, int32(v))
	case uint16:
		return p.NewNumberVar(Uint16Type, int32(v))
	case int32:
		return p.NewNumberVar(Int32Type, int32(v))
	case uint32:
		return p.NewNumberVar(Uint32Type, int32(v))
	case int64:
		// TODO(safchain)
	case uint64:
		// TODO(safchain)
	case []byte:
		return p.NewByteArrayVar(v)
	case string:
		return p.NewByteArrayVar([]byte(v))
	}

	return nil, fmt.Errorf("variable type unknown")
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
