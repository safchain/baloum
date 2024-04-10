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
	var r RegisterAllocator

	for reg := asm.R4; reg != asm.R10; reg++ {
		r.available = append(r.available, reg)
	}

	return &r
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
	pb *ProgramBuilder
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
		derefVar, err = vr.pb.NewNumberVar(Int8Type, int32(0))
	case UInt8PtrType:
		derefVar, err = vr.pb.NewNumberVar(UInt8Type, int32(0))
	case Int16PtrType:
		derefVar, err = vr.pb.NewNumberVar(Int16Type, int32(0))
	case UInt16PtrType:
		derefVar, err = vr.pb.NewNumberVar(UInt16Type, int32(0))
	case Int32PtrType:
		derefVar, err = vr.pb.NewNumberVar(Int32Type, int32(0))
	case UInt32PtrType:
		derefVar, err = vr.pb.NewNumberVar(UInt32Type, int32(0))
	case Int64PtrType:
		derefVar, err = vr.pb.NewNumberVar(Int64Type, int32(0))
	case UInt64PtrType:
		derefVar, err = vr.pb.NewNumberVar(UInt64Type, int32(0))
	default:
		return nil, errors.New("not a pointer")
	}

	reg1, reg2, err := vr.pb.regAlloc.Alloc2()
	if err != nil {
		return nil, err
	}
	defer vr.pb.regAlloc.Free(reg1, reg2)

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.LoadMem(reg1, asm.RFP, vr.Addr, vr.Sizeof()),
		asm.LoadMem(reg2, reg1, 0, derefVar.Sizeof()),
		asm.StoreMem(asm.RFP, derefVar.Addr, reg2, derefVar.Sizeof()),
	}...)

	return derefVar, nil
}

func (vr Variable) Ptr() (asm.Register, error) {
	reg, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		return 0, err
	}

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.Addr)),
	}...)

	return reg, nil
}

func (vr Variable) PtrReg(reg asm.Register) {
	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.Addr)),
	}...)
}

func (vr Variable) Load(offset int) (asm.Register, error) {
	regPtr, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		return 0, err
	}
	defer vr.pb.regAlloc.Free(regPtr)

	regVal, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		return 0, err
	}

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(regPtr, asm.RFP),
		asm.LoadMem(regVal, regPtr, vr.Addr+int16(offset), vr.Sizeof()),
	}...)

	return regVal, nil
}

func (vr Variable) Store(reg asm.Register) error {
	regVal, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		return err
	}
	defer vr.pb.regAlloc.Free(regVal)

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(regVal, asm.RFP),
		asm.StoreMem(regVal, int16(vr.Addr), reg, asm.DWord),
	}...)

	return nil
}

func (p *Program) Edit(opts ProgramBuilderOpts) *ProgramBuilder {
	opts.applyDefault()

	return &ProgramBuilder{
		program:  p,
		opts:     opts,
		regAlloc: NewRegisterAllocator(),
	}
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
