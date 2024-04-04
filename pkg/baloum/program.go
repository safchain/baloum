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

type RegisterAllocator struct {
	available []asm.Register
}

func (r *RegisterAllocator) Alloc() (asm.Register, error) {
	// TODO reverse order to keep R1, R2, R3 available as much as possible

	if len(r.available) == 0 {
		return 0, errors.New("no register available")
	}

	reg := r.available[0]
	r.available = r.available[1:]
	return reg, nil
}

func (r *RegisterAllocator) Alloc2() (asm.Register, asm.Register, error) {
	reg1, err := r.Alloc()
	if err != nil {
		return 0, 0, err
	}

	reg2, err := r.Alloc()
	if err != nil {
		return 0, 0, err
	}

	return reg1, reg2, nil
}

func (r *RegisterAllocator) Free(regs ...asm.Register) {
	for _, reg := range regs {
		if reg > 3 && reg < 10 {
			r.available = append([]asm.Register{reg}, r.available...)
		}
	}
}

func NewRegisterAllocator() *RegisterAllocator {
	r := &RegisterAllocator{}

	for reg := asm.R4; reg != asm.R10; reg++ {
		r.available = append(r.available, reg)
	}

	return r
}

type VariableType int

const (
	Int8Type VariableType = iota
	UInt8Type
	Int16Type
	UInt16Type
	Int32Type
	UInt32Type
	Int64Type
	UInt64Type
	Int8PtrType
	UInt8PtrType
	Int16PtrType
	UInt16PtrType
	Int32PtrType
	UInt32PtrType
	Int64PtrType
	UInt64PtrType
)

func (vt VariableType) IsPtr() bool {
	return vt == UInt8PtrType || vt == UInt16PtrType || vt == UInt32PtrType || vt == UInt64PtrType
}

func (vt VariableType) Sizeof() asm.Size {
	switch vt {
	case Int8Type, UInt8Type:
		return asm.Byte
	case Int16Type, UInt16Type:
		return asm.Half
	case Int32Type, UInt32Type:
		return asm.Word
	case Int64Type, UInt64Type:
		return asm.DWord
	}

	if vt.IsPtr() {
		return asm.DWord
	}

	return asm.InvalidSize
}

type Variable struct {
	Type VariableType
	Addr int16

	// internals
	pe *ProgramEditor
}

func (vr Variable) IsPtr() bool {
	return vr.Type.IsPtr()
}

func (vr Variable) Sizeof() asm.Size {
	return vr.Type.Sizeof()
}

func (vr Variable) Deref() (*Variable, error) {
	var (
		derefVar *Variable
		err      error
	)

	switch vr.Type {
	case Int8PtrType:
		derefVar, err = vr.pe.NewNumberVar(Int8Type, int32(0))
	case UInt8PtrType:
		derefVar, err = vr.pe.NewNumberVar(UInt8Type, int32(0))
	case Int16PtrType:
		derefVar, err = vr.pe.NewNumberVar(Int16Type, int32(0))
	case UInt16PtrType:
		derefVar, err = vr.pe.NewNumberVar(UInt16Type, int32(0))
	case Int32PtrType:
		derefVar, err = vr.pe.NewNumberVar(Int32Type, int32(0))
	case UInt32PtrType:
		derefVar, err = vr.pe.NewNumberVar(UInt32Type, int32(0))
	case Int64PtrType:
		derefVar, err = vr.pe.NewNumberVar(Int64Type, int32(0))
	case UInt64PtrType:
		derefVar, err = vr.pe.NewNumberVar(UInt64Type, int32(0))
	default:
		return nil, errors.New("not a pointer")
	}

	reg1, reg2, err := vr.pe.regAlloc.Alloc2()
	if err != nil {
		return nil, err
	}
	defer vr.pe.regAlloc.Free(reg1, reg2)

	vr.pe.insts = append(vr.pe.insts, asm.Instructions{
		asm.LoadMem(reg1, asm.RFP, vr.Addr, vr.Sizeof()),
		asm.LoadMem(reg2, reg1, 0, derefVar.Sizeof()),
		asm.StoreMem(asm.RFP, derefVar.Addr, reg2, derefVar.Sizeof()),
	}...)

	return derefVar, nil
}

func (vr Variable) Ptr() (asm.Register, error) {
	reg, err := vr.pe.regAlloc.Alloc()
	if err != nil {
		return 0, err
	}

	vr.pe.insts = append(vr.pe.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.Addr)),
	}...)

	return reg, nil
}

func (vr Variable) PtrReg(reg asm.Register) {
	vr.pe.insts = append(vr.pe.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.Addr)),
	}...)
}

func (vr Variable) Load(offset int) (asm.Register, error) {
	regPtr, err := vr.pe.regAlloc.Alloc()
	if err != nil {
		return 0, err
	}
	defer vr.pe.regAlloc.Free(regPtr)

	regVal, err := vr.pe.regAlloc.Alloc()
	if err != nil {
		return 0, err
	}

	vr.pe.insts = append(vr.pe.insts, asm.Instructions{
		asm.Mov.Reg(regPtr, asm.RFP),
		asm.LoadMem(regVal, regPtr, vr.Addr+int16(offset), vr.Sizeof()),
	}...)

	return regVal, nil
}

func (vr Variable) Store(reg asm.Register) error {
	regVal, err := vr.pe.regAlloc.Alloc()
	if err != nil {
		return err
	}
	defer vr.pe.regAlloc.Free(regVal)

	vr.pe.insts = append(vr.pe.insts, asm.Instructions{
		asm.Mov.Reg(regVal, asm.RFP),
		asm.StoreMem(regVal, int16(vr.Addr), reg, asm.DWord),
	}...)

	return nil
}

type ProgramEditor struct {
	program   *Program
	opts      ProgramEditorOpts
	insts     asm.Instructions
	blocks    []stackMemBlock
	symbolIdx int
	regAlloc  *RegisterAllocator
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
		program:  p,
		opts:     opts,
		regAlloc: NewRegisterAllocator(),
	}
}

func (p *ProgramEditor) Commit() {
	// TODO optimise :
	// MovReg dst: r4 src: rfp (8)
	// StXMemDW dst: r4 src: r0 off: -24 imm: 0 (8)
	// MovReg dst: r4 src: rfp (8)
	// LdXMemW dst: r5 src: r4 off: -24 imm: 0 (8)

	// relocate symbol
	for i := len(p.insts) - 1; i > 0; i-- {
		if symbol := p.insts[i-1].Symbol(); strings.HasSuffix(symbol, JumpSymbolType) {
			p.insts[i] = p.insts[i].WithSymbol(symbol)
			p.insts[i-1] = p.insts[i-1].WithSymbol("")
		}
	}
	p.program.insts = append(p.program.insts, p.insts...)
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
		case *Variable:
			if arg.IsPtr() {
				p.insts = append(p.insts,
					asm.Mov.Reg(reg, asm.RFP),
					asm.Add.Imm(reg, int32(arg.Addr)),
				)
			} else {
				p.insts = append(p.insts,
					asm.LoadMem(reg, asm.RFP, arg.Addr, arg.Sizeof()),
				)
			}
		case nil:
		default:
			if v, err := ToInt32(arg); err == nil {
				return fmt.Errorf("unknown argument type %v", arg)
			} else {
				p.insts = append(p.insts,
					asm.Mov.Imm(reg, v),
				)
			}
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
		if !var1.IsPtr() {
			return errors.New("invalid variable type")
		}

		size := int16(len(str))

		var (
			regPtr asm.Register
			regVal asm.Register
			err    error
		)
		defer p.regAlloc.Free(regPtr, regVal)

		regPtr, err = var1.Ptr()
		if err != nil {
			return err
		}

		regVal, err = p.regAlloc.Alloc()
		if err != nil {
			return err
		}

		for i := int16(0); i != size; i++ {
			p.insts = append(p.insts,
				asm.LoadMem(regVal, regPtr, i, asm.Byte),
				asm.JNE.Imm(regVal, int32(str[i]), falseSym),
			)
		}

		// TODO add PtrInst and LoadInst to Variable to ease the development

		p.insts = append(p.insts,
			asm.LoadMem(regVal, regPtr, size, asm.Byte),
			asm.JEq.Imm(regVal, 0, trueSym),
			asm.Ja.Label(falseSym),
		)

		return nil
	}
}

func (p *ProgramEditor) StrCmp(var1 *Variable, var2 *Variable, unroll int) func(trueSym, falseSym string) error {
	return func(trueSym string, falseSym string) error {
		if !var1.IsPtr() || !var2.IsPtr() {
			return errors.New("invalid variable type")
		}

		var (
			regPtr1, regVal1 asm.Register
			regPtr2, regVal2 asm.Register
			err              error
		)
		defer p.regAlloc.Free(regPtr1, regVal1, regPtr2, regVal2)

		regPtr1, err = var1.Ptr()
		if err != nil {
			return err
		}

		regPtr2, err = var2.Ptr()
		if err != nil {
			return err
		}

		regVal1, regVal2, err = p.regAlloc.Alloc2()
		if err != nil {
			return err
		}

		addr1, addr2 := var1.Addr, var2.Addr

		for i := 0; i != unroll; i++ {
			// stack overflow
			if addr1 == 0 || addr2 == 0 {
				break
			}

			p.insts = append(p.insts,
				asm.LoadMem(regVal1, regPtr1, int16(i), asm.Byte),
				asm.LoadMem(regVal2, regPtr2, int16(i), asm.Byte),
				asm.JNE.Reg(regVal1, regVal2, falseSym),
				asm.Or.Reg(regVal1, regVal2),
				asm.JEq.Imm(regVal1, int32(0), trueSym),
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

func (p *ProgramEditor) IsNull(var1 interface{}) func(trueSym, falseSym string) error {
	return p.Equal(var1, uint32(0))
}

func (p *ProgramEditor) IsNotNull(var1 interface{}) func(trueSym, falseSym string) error {
	return p.NotEqual(var1, uint32(0))
}

func (p *ProgramEditor) NotEqual(var1 interface{}, var2 interface{}) func(trueSym, falseSym string) error {
	fnc := p.Equal(var1, var2)
	return func(trueSym, falseSym string) error {
		return fnc(falseSym, trueSym)
	}
}

func (p *ProgramEditor) Equal(var1 interface{}, var2 interface{}) func(trueSym, falseSym string) error {
	return func(trueSym string, falseSym string) error {
		var (
			regVal1 asm.Register
			regVal2 asm.Register
			err     error
		)
		defer p.regAlloc.Free(regVal1, regVal2)

		switch v1 := var1.(type) {
		case *Variable:
			switch v2 := var2.(type) {
			case *Variable:
				regVal1, err = v1.Load(0)
				if err != nil {
					return err
				}

				regVal2, err = v2.Load(0)
				if err != nil {
					return err
				}

				p.insts = append(p.insts,
					asm.JEq.Reg(regVal1, regVal2, trueSym),
					asm.Ja.Label(falseSym),
				)
			case int8, uint8, int16, uint16, int32, uint32, int64, uint64:
				val2, err := ToInt32(v2)
				if err != nil {
					return err
				}

				regVal1, err = v1.Load(0)
				if err != nil {
					return err
				}

				p.insts = append(p.insts,
					asm.JEq.Imm(regVal1, val2, trueSym),
					asm.Ja.Label(falseSym),
				)
			default:
				return errors.New("unknown type")
			}
		case int8, uint8, int16, uint16, int32, uint32, int64, uint64:
			val1, err := ToInt32(v1)
			if err != nil {
				return err
			}

			switch v2 := var2.(type) {
			case *Variable:
				regVal2, err = v2.Load(0)
				if err != nil {
					return err
				}

				p.insts = append(p.insts,
					asm.JEq.Imm(regVal2, val1, trueSym),
					asm.Ja.Label(falseSym),
				)
			case int8, uint8, int16, uint16, int32, uint32, int64, uint64:
				val2, err := ToInt32(v2)
				if err != nil {
					return err
				}

				p.insts = append(p.insts,
					asm.Mov.Imm(asm.R2, val1),
					asm.JEq.Imm(asm.R2, val2, trueSym),
					asm.Ja.Label(falseSym),
				)
			default:
				return errors.New("unknown type")
			}
		default:
			return errors.New("unknown type")
		}

		return nil
	}
}

func (p *ProgramEditor) MapLookup(mapName string, key *Variable, value *Variable) error {
	if !value.IsPtr() {
		return errors.New("value is not a pointer type")
	}

	key.PtrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
		asm.FnMapLookupElem.Call(),
	)

	return value.Store(asm.R0)
}

func (p *ProgramEditor) MapUpdate(mapName string, key *Variable, value *Variable, ret *Variable, kind MapUpdateType) error {
	key.PtrReg(asm.R2)
	value.PtrReg(asm.R3)

	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R4, int32(kind)),
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
		asm.FnMapUpdateElem.Call(),
	)

	if ret != nil {
		return ret.Store(asm.R0)
	}
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
		falseSym = "else-" + symSuffix
	}

	if err := cond(trueSym, falseSym); err != nil {
		return err
	}
	p.insts[p.lastInstIdx()] = p.insts[p.lastInstIdx()].WithSymbol(trueSym)

	if then != nil {
		if err := then(); err != nil {
			return err
		}
	}

	p.insts = append(p.insts,
		asm.Ja.Label("endif-"+symSuffix).WithSymbol("else-"+symSuffix),
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
	addr, err := p.StackAlloc(int16(asm.DWord.Sizeof()))
	if err != nil {
		return nil, err
	}
	variable := &Variable{Type: kind, Addr: addr, pe: p}

	regValue, err := p.regAlloc.Alloc()
	if err != nil {
		return nil, err
	}
	defer p.regAlloc.Free(regValue)

	p.insts = append(p.insts,
		asm.Mov.Imm(regValue, value),
		asm.StoreMem(asm.RFP, addr, regValue, asm.DWord),
	)

	return variable, nil
}

func (p *ProgramEditor) NewByteArrayVar(value []byte) (*Variable, error) {
	addr, insts, err := p.stackBytes(value)
	if err != nil {
		return nil, err
	}
	variable := &Variable{Type: UInt8PtrType, Addr: addr, pe: p}

	p.insts = append(p.insts, insts...)

	return variable, nil
}

func (p *ProgramEditor) NewPtrVar(kind VariableType) (*Variable, error) {
	if !kind.IsPtr() {
		return nil, errors.New("not a pointer type")
	}

	addr, err := p.StackAlloc(int16(asm.DWord.Sizeof()))
	if err != nil {
		return nil, err
	}
	return &Variable{Type: kind, Addr: addr, pe: p}, nil
}

func (p *ProgramEditor) NewVar(value interface{}) (*Variable, error) {
	switch v := value.(type) {
	case int8:
		return p.NewNumberVar(Int8Type, int32(v))
	case uint8:
		return p.NewNumberVar(UInt8Type, int32(v))
	case int16:
		return p.NewNumberVar(Int16Type, int32(v))
	case uint16:
		return p.NewNumberVar(UInt16Type, int32(v))
	case int32:
		return p.NewNumberVar(Int32Type, int32(v))
	case uint32:
		return p.NewNumberVar(UInt32Type, int32(v))
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
