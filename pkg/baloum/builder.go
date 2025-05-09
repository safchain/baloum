/*
Copyright © 2024 SYLVAIN AFCHAIN

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
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"

	"github.com/cilium/ebpf/asm"
	"golang.org/x/exp/slices"
)

const (
	// STACK_ALIGN is the stack alignment
	STACK_ALIGN = asm.DWord
)

// BuilderError is the type for the builder error
type BuilderError struct {
	err        error
	stacktrace []byte
}

// NewBuilderError creates a new builder error
func NewBuilderError(err error) *BuilderError {
	p := &BuilderError{
		err:        err,
		stacktrace: make([]byte, 4096),
	}
	runtime.Stack(p.stacktrace, false)
	return p
}

// Error returns the error message
func (b *BuilderError) Error() string {
	return b.err.Error()
}

// Stack returns the stack trace
func (b *BuilderError) Stack() []byte {
	return b.stacktrace
}

// Condition is the type for the condition
type Condition func(trueSym, falseSym string)

type stackMemBlock struct {
	addr  int16
	size  int16
	inuse bool
}

const (
	// RNULL is used to mark a register as not usable
	RNULL = asm.Register(99)
)

// isVarReg variable register in opposite of param register
func isVarReg(reg asm.Register) bool {
	return reg >= asm.R6 && reg < asm.R10
}

// RegisterAllocator is the type for the register allocator
type RegisterAllocator struct {
	available  []asm.Register
	onExausted func()
}

// Alloc allocates a register
func (r *RegisterAllocator) Alloc() (asm.Register, error) {
	if len(r.available) == 0 {
		// try to free some registers
		r.onExausted()

		// still no register available
		if len(r.available) == 0 {
			return 0, errors.New("no register available")
		}
	}

	reg := r.available[0]
	r.available = r.available[1:]
	return reg, nil
}

// Alloc2 allocates two registers
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

// Free frees a register
func (r *RegisterAllocator) Free(regs ...asm.Register) {
	for _, reg := range regs {
		if isVarReg(reg) && reg != RNULL {
			r.available = append([]asm.Register{reg}, r.available...)
		}
	}
}

func newRegisterAllocator(onExausted func()) *RegisterAllocator {
	r := RegisterAllocator{
		onExausted: onExausted,
	}

	for reg := asm.R6; reg != asm.R10; reg++ {
		r.available = append(r.available, reg)
	}

	return &r
}

// VariableType is the type for the variable type
type VariableType int

const (
	// Int8Type is the type for the int8 variable
	Int8Type VariableType = iota
	// UInt8Type is the type for the uint8 variable
	UInt8Type
	// Int16Type is the type for the int16 variable
	Int16Type
	// UInt16Type is the type for the uint16 variable
	UInt16Type
	// Int32Type is the type for the int32 variable
	Int32Type
	// UInt32Type is the type for the uint32 variable
	UInt32Type
	// Int64Type is the type for the int64 variable
	Int64Type
	// UInt64Type is the type for the uint64 variable
	UInt64Type
	// PtrType is the type for the pointer variable
	PtrType
	// CtxType is the type for the context variable
	CtxType
)

// IsPtr checks if a variable is a pointer
func (vt VariableType) IsPtr() bool {
	return vt == PtrType || vt == CtxType
}

// AsmSizeof returns the size of the variable in bytes
func (vt VariableType) AsmSizeof() asm.Size {
	switch vt {
	case Int8Type, UInt8Type:
		return asm.Byte
	case Int16Type, UInt16Type:
		return asm.Half
	case Int32Type, UInt32Type:
		return asm.Word
	case Int64Type, UInt64Type:
		return asm.DWord
	case PtrType:
		return asm.DWord
	}
	return asm.InvalidSize
}

// Sizeof returns the size of the variable in bytes
func (vt VariableType) Sizeof() int {
	return vt.AsmSizeof().Sizeof()
}

// Variable is the type for the variable
type Variable struct {
	// Type is the type of the variable
	Type VariableType

	addr int16
	reg  asm.Register
	pb   *ProgramBuilder
}

// NewVariable creates a new variable
func newVariable(kind VariableType, addr int16, reg asm.Register, pb *ProgramBuilder) *Variable {
	return &Variable{
		Type: kind,
		addr: addr,
		reg:  reg,
		pb:   pb,
	}
}

// IsPtr checks if a variable is a pointer
func (vr *Variable) IsPtr() bool {
	return vr.Type.IsPtr()
}

// IsCtx checks if a variable is a context variable
func (vr *Variable) IsCtx() bool {
	return vr.Type == CtxType
}

// AsmSizeof returns the size of the variable in bytes
func (vr *Variable) AsmSizeof() asm.Size {
	return vr.Type.AsmSizeof()
}

// Sizeof returns the size of the variable in bytes
func (vr *Variable) Sizeof() int {
	return vr.Type.Sizeof()
}

// InReg checks if a variable is in a register
func (vr *Variable) inReg() bool {
	return vr.reg != RNULL
}

// Deref dereferences a pointer variable
func (vr *Variable) Deref(vt VariableType, offset int) *Variable {
	if !vr.IsPtr() {
		vr.pb.setError("invalid variable type")
	}

	vr.load()

	derefVar, reg := vr.pb.newVarReg(vt)

	vr.pb.insts = append(vr.pb.insts,
		asm.LoadMem(reg, vr.reg, int16(offset), derefVar.AsmSizeof()),
	)

	return derefVar
}

func (vr *Variable) Add(offset int) *Variable {
	reg := vr.load()

	newVar, newReg := vr.pb.newVarReg(vr.Type)

	vr.pb.insts = append(vr.pb.insts,
		asm.Mov.Reg(newReg, reg),
		asm.Add.Imm(newReg, int32(offset)),
	)

	return newVar
}

func (vr *Variable) ptrReg(reg asm.Register) {
	vr.persist()

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.addr)),
	}...)
}

func (vr *Variable) load() asm.Register {
	if vr.inReg() {
		return vr.reg
	}

	regVal, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		vr.pb.setError(err)
	}

	vr.loadToReg(regVal)

	return regVal
}

func (vr *Variable) loadToReg(reg asm.Register) {
	if vr.inReg() {
		if vr.reg == reg {
			return
		}

		vr.pb.insts = append(vr.pb.insts,
			asm.Mov.Reg(reg, vr.reg),
		)
	} else {
		if vr.IsPtr() {
			vr.pb.insts = append(vr.pb.insts,
				asm.Mov.Reg(reg, asm.RFP),
				asm.Add.Imm(reg, int32(vr.addr)),
			)
		} else {
			vr.pb.insts = append(vr.pb.insts,
				asm.LoadMem(reg, asm.RFP, vr.addr, vr.AsmSizeof()),
			)
		}
	}

	if isVarReg(reg) {
		vr.setReg(reg)
	}
}

func (vr *Variable) setReg(reg asm.Register) {
	vr.pb.regAlloc.Free(vr.reg)
	vr.reg = reg
}

func (vr *Variable) persist() {
	if !vr.inReg() {
		return
	}

	if vr.addr == math.MaxInt16 {
		vr.addr = vr.pb.stackAlloc(int16(asm.DWord.Sizeof()))
	}

	vr.pb.insts = append(vr.pb.insts,
		asm.StoreMem(asm.RFP, int16(vr.addr), vr.reg, vr.AsmSizeof()),
	)

	vr.setReg(RNULL)
}

type jmpSymbolGenerator struct {
	idx int
}

type enterJmpSymbolBlock struct {
	idx int
}

func (s *jmpSymbolGenerator) enterBlock() *enterJmpSymbolBlock {
	s.idx++
	return &enterJmpSymbolBlock{idx: s.idx}
}

func (e *enterJmpSymbolBlock) getSymbol(prefix string) string {
	return fmt.Sprintf("%s-%d-%s", prefix, e.idx, JumpSymbolType)
}

// ProgramBuilderOpts is the type for the program builder options
type ProgramBuilderOpts struct {
	StackSize int
}

func (p *ProgramBuilderOpts) applyDefault() {
	if p.StackSize == 0 {
		p.StackSize = DEFAULT_STACK_SIZE
	}
}

// ProgramBuilder is the type for the program builder
type ProgramBuilder struct {
	program   *Program
	opts      ProgramBuilderOpts
	insts     asm.Instructions
	blocks    []stackMemBlock
	jmpSymGen jmpSymbolGenerator
	regAlloc  *RegisterAllocator
	err       error
	variables []*Variable
}

// NewProgramBuilder creates a new program builder
func NewProgramBuilder(p *Program, opts ProgramBuilderOpts) *ProgramBuilder {
	opts.applyDefault()

	pb := &ProgramBuilder{
		program: p,
		opts:    opts,
	}

	pb.regAlloc = newRegisterAllocator(pb.onRegExausted)

	return pb
}

// Error returns the error
func (p *ProgramBuilder) Error() error {
	return p.err
}

func (p *ProgramBuilder) setError(arg1 interface{}, args ...interface{}) {
	if p.err == nil {
		switch arg := arg1.(type) {
		case string:
			p.err = NewBuilderError(fmt.Errorf(arg, args...))
		case error:
			p.err = NewBuilderError(arg)
		default:
			p.err = NewBuilderError(errors.New("unknown error"))
		}
	}
}

func deadCodeElimination(insts asm.Instructions) asm.Instructions {
	// super naive dead code elimination
	var (
		cleaned asm.Instructions
		unreach bool
	)
	for _, inst := range insts {
		if inst.Symbol() != "" {
			unreach = false
		}

		if !unreach {
			cleaned = append(cleaned, inst)
		}

		switch inst.OpCode {
		case asm.Return().OpCode:
			unreach = true
		}
	}

	return cleaned
}

func (p *ProgramBuilder) varByReg(reg asm.Register) *Variable {
	for _, v := range p.variables {
		if v.reg == reg {
			return v
		}
	}
	return nil
}

func (p *ProgramBuilder) invalidateReg(reg asm.Register) {
	for _, v := range p.variables {
		if v.inReg() && v.reg == reg {
			targetReg, err := p.regAlloc.Alloc()
			if err != nil {
				p.setError(err)
			}

			if targetReg != reg {
				p.insts = append(p.insts,
					asm.Mov.Reg(targetReg, reg),
				)

				v.setReg(targetReg)
			}

			break
		}
	}
}

func (p *ProgramBuilder) invalidateRegs(regs ...asm.Register) {
	for _, reg := range regs {
		p.invalidateReg(reg)
	}
}

// CallFn calls a function
func (p *ProgramBuilder) CallFn(fn asm.BuiltinFunc, symbol ...string) asm.Instructions {
	inst := fn.Call()
	if len(symbol) > 0 {
		inst = inst.WithSymbol(symbol[0])
	}

	return asm.Instructions{
		inst,
	}
}

// Commit commits the program
func (p *ProgramBuilder) Commit() error {
	// relocate symbols
	for i := len(p.insts) - 1; i > 0; i-- {
		if symbol := p.insts[i-1].Symbol(); strings.HasSuffix(symbol, JumpSymbolType) {
			p.insts[i] = p.insts[i].WithSymbol(symbol)
			p.insts[i-1] = p.insts[i-1].WithSymbol("")
		}
	}

	p.insts = deadCodeElimination(p.insts)

	p.program.insts = append(p.program.insts, p.insts...)

	return p.err
}

func (p *ProgramBuilder) stackAlloc(size int16) int16 {
	alignSizeOf := int16(STACK_ALIGN.Sizeof())

	// 32bit alignment
	if size%alignSizeOf != 0 {
		size += alignSizeOf - size%alignSizeOf
	}

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

			return inuse.addr
		}
		lastAddr = block.addr
	}

	if lastAddr-int16(size) < -int16(p.opts.StackSize) {
		p.setError("out of stack memory: %d vs %d", size, p.opts.StackSize)
	}

	block := stackMemBlock{
		addr:  lastAddr - int16(size),
		size:  size,
		inuse: true,
	}
	p.blocks = append(p.blocks, block)

	return block.addr
}

func (p *ProgramBuilder) stackFree(addr int16) {
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

func (p *ProgramBuilder) stackBytes(bytes []byte) (int16, asm.Instructions) {
	var insts asm.Instructions

	addr := p.stackAlloc(int16(len(bytes)))
	ptr := addr

	for len(bytes) > 0 {
		switch l := len(bytes); {
		case l <= 1:
			value := int32(bytes[0])
			insts = append(insts,
				asm.Mov.Imm(asm.R2, int32(value)),
				asm.StoreMem(asm.RFP, ptr, asm.R2, asm.Byte),
			)
			ptr += int16(asm.Byte.Sizeof())
			bytes = bytes[1:]
		case l >= 2 && l < 4:
			value := int32(binary.NativeEndian.Uint16(bytes[0:2]))
			insts = append(insts,
				asm.Mov.Imm(asm.R2, int32(value)),
				asm.StoreMem(asm.RFP, ptr, asm.R2, asm.Half),
			)
			ptr += int16(asm.Half.Sizeof())
			bytes = bytes[2:]
		case l >= 4 && l < 8:
			value := binary.NativeEndian.Uint32(bytes[0:4])
			insts = append(insts,
				asm.Mov.Imm(asm.R2, int32(value)),
				asm.StoreMem(asm.RFP, ptr, asm.R2, asm.Word),
			)
			ptr += int16(asm.Word.Sizeof())
			bytes = bytes[4:]
		default:
			value := uint64(binary.NativeEndian.Uint64(bytes[0:8]))
			insts = append(insts,
				asm.LoadImm(asm.R2, int64(value), asm.DWord),
				asm.StoreMem(asm.RFP, ptr, asm.R2, asm.DWord),
			)
			ptr += int16(asm.DWord.Sizeof())
			bytes = bytes[8:]
		}
	}

	return addr, insts
}

// Return returns a value from a function
func (p *ProgramBuilder) Return(code int) {
	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R0, int32(code)),
		asm.Return(),
	)
}

// Printk prints a formatted string
func (p *ProgramBuilder) Printk(format string, args ...interface{}) {
	if len(args) > 3 {
		p.setError("maximum of args excedeed")
		args = args[0:3]
	}

	// be sure that R0, R1 are not used by a ctx variable
	p.invalidateRegs(asm.R0, asm.R1)

	// format
	addr, insts := p.stackBytes(Str2Bytes(format))
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
			arg.loadToReg(reg)
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
			p.setError(err)
		}
	}

	p.insts = append(p.insts,
		p.CallFn(asm.FnTracePrintk)...,
	)

	p.stackFree(addr)
}

// StrStaticCmp compares a variable with a static string
func (p *ProgramBuilder) StrStaticCmp(var1 *Variable, str string) Condition {
	return func(trueSym, falseSym string) {
		if !var1.IsPtr() {
			p.setError("invalid variable type")
		}

		size := int16(len(str))

		var (
			regPtr = var1.load()
			regVal asm.Register
			err    error
		)
		defer p.regAlloc.Free(regVal)

		if regVal, err = p.regAlloc.Alloc(); err != nil {
			p.setError(err)
		}

		for i := int16(0); i != size; i++ {
			p.insts = append(p.insts,
				asm.LoadMem(regVal, regPtr, i, asm.Byte),
				asm.JNE.Imm(regVal, int32(str[i]), falseSym),
			)
		}

		p.insts = append(p.insts,
			asm.LoadMem(regVal, regPtr, size, asm.Byte),
			asm.JEq.Imm(regVal, 0, trueSym),
			asm.Ja.Label(falseSym),
		)
	}
}

// StrCmp compares two variables
func (p *ProgramBuilder) StrCmp(var1 *Variable, var2 *Variable, unroll int) Condition {
	return func(trueSym string, falseSym string) {
		if !var1.IsPtr() || !var2.IsPtr() {
			p.setError("invalid variable type")
		}

		var (
			regPtr1, regVal1 asm.Register
			regPtr2, regVal2 asm.Register
			err              error
		)
		defer p.regAlloc.Free(regVal1, regVal2)

		regPtr1, regPtr2 = var1.load(), var2.load()

		regVal1, regVal2, err = p.regAlloc.Alloc2()
		if err != nil {
			p.setError(err)
		}

		addr1, addr2 := var1.addr, var2.addr

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
	}
}

// StrIn checks if a variable is in a list of static strings
func (p *ProgramBuilder) StrIn(var1 *Variable, strs ...string) Condition {
	var conds []Condition
	for _, str := range strs {
		conds = append(conds, p.StrStaticCmp(var1, str))
	}
	return p.Or(conds...)
}

// True returns a condition that always returns true
func (p *ProgramBuilder) True() Condition {
	return func(trueSym, falseSym string) {
		p.insts = append(p.insts,
			asm.Ja.Label(trueSym),
		)
	}
}

// False returns a condition that always returns false
func (p *ProgramBuilder) False() Condition {
	return func(trueSym, falseSym string) {
		p.insts = append(p.insts,
			asm.Ja.Label(falseSym),
		)
	}
}

// And returns a condition that returns true if all conditions are true
func (p *ProgramBuilder) And(conds ...Condition) Condition {
	return func(trueSym, falseSym string) {
		for i, cond := range conds {
			sbg := p.jmpSymGen.enterBlock()

			if i == len(conds)-1 {
				cond(trueSym, falseSym)
			} else {
				nextCondSym := sbg.getSymbol("next-cond")

				cond(nextCondSym, falseSym)
				p.updateLastInstSymbol(nextCondSym)
			}
		}
	}
}

// Or returns a condition that returns true if any of the conditions are true
func (p *ProgramBuilder) Or(conds ...Condition) Condition {
	return func(trueSym, falseSym string) {
		for i, cond := range conds {
			sbg := p.jmpSymGen.enterBlock()

			if i == len(conds)-1 {
				cond(trueSym, falseSym)
			} else {
				nextCondSym := sbg.getSymbol("next-cond")

				cond(trueSym, nextCondSym)
				p.updateLastInstSymbol(nextCondSym)
			}
		}
	}
}

// IsNull returns a condition that returns true if a variable is null
func (p *ProgramBuilder) IsNull(var1 *Variable) Condition {
	return p.Equal(var1, uint32(0))
}

// IsNotNull returns a condition that returns true if a variable is not null
func (p *ProgramBuilder) IsNotNull(var1 *Variable) Condition {
	return p.NotEqual(var1, uint32(0))
}

// NotEqual returns a condition that returns true if a variable is not equal to another variable
func (p *ProgramBuilder) NotEqual(var1 *Variable, var2 interface{}) Condition {
	return p.Not(p.Equal(var1, var2))
}

// Not returns a condition that returns true if a condition is false
func (p *ProgramBuilder) Not(cond Condition) Condition {
	return func(trueSym, falseSym string) {
		cond(falseSym, trueSym)
	}
}

// Equal returns a condition that returns true if a variable is equal to another variable
func (p *ProgramBuilder) Equal(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JEq)
}

// Greater returns a condition that returns true if a variable is greater than another variable
func (p *ProgramBuilder) Greater(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JGT)
}

// GreaterEqual returns a condition that returns true if a variable is greater than or equal to another variable
func (p *ProgramBuilder) GreaterEqual(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JGE)
}

// Lesser returns a condition that returns true if a variable is less than another variable
func (p *ProgramBuilder) Lesser(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JLT)
}

// LesserEqual returns a condition that returns true if a variable is less than or equal to another variable
func (p *ProgramBuilder) LesserEqual(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JLE)
}

func (p *ProgramBuilder) cmp(var1 *Variable, var2 interface{}, cmpOp asm.JumpOp) Condition {
	return func(trueSym string, falseSym string) {
		var (
			regVal1 = var1.load()
			regVal2 asm.Register
		)

		switch v2 := var2.(type) {
		case *Variable:
			regVal2 = v2.load()

			p.insts = append(p.insts,
				cmpOp.Reg(regVal1, regVal2, trueSym),
				asm.Ja.Label(falseSym),
			)
		case int, int8, uint8, int16, uint16, int32, uint32:
			val2, err := ToInt32(v2)
			if err != nil {
				p.setError(err)
			}

			p.insts = append(p.insts,
				cmpOp.Imm(regVal1, val2, trueSym),
				asm.Ja.Label(falseSym),
			)
		case int64, uint64:
			val2, err := ToInt64(v2)
			if err != nil {
				p.setError(err)
			}

			regVal2, err := p.regAlloc.Alloc()
			if err != nil {
				p.setError(err)
			}
			defer p.regAlloc.Free(regVal2)

			p.insts = append(p.insts,
				asm.LoadImm(regVal2, val2, asm.DWord),
				cmpOp.Reg(regVal1, regVal2, trueSym),
				asm.Ja.Label(falseSym),
			)
		default:
			p.setError("unknown type: %v", var2)
		}
	}
}

func (p *ProgramBuilder) tailCall(ctx *Variable, mapName string, fd int, value interface{}, ret *Variable) {
	// be sure that R1 is not used by a ctx variable
	if v := p.varByReg(asm.R1); v != nil && v != ctx {
		p.invalidateReg(asm.R1)
	}

	ctx.loadToReg(asm.R1)

	switch v := value.(type) {
	case *Variable:
		v.loadToReg(asm.R3)
	default:
		i, err := ToInt32(value)
		if err != nil {
			p.setError(err)
		}

		p.insts = append(p.insts,
			asm.Mov.Imm(asm.R3, i),
		)
	}

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R2, fd).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnTailCall)...)

	ret.setReg(asm.R0)
}

// TailCallFD calls a function with a file descriptor
func (p *ProgramBuilder) TailCallFD(ctx *Variable, fd int, value interface{}, ret *Variable) {
	p.tailCall(ctx, "", fd, value, ret)
}

// TailCall calls a function with a map name
func (p *ProgramBuilder) TailCall(ctx *Variable, mapName string, value interface{}, ret *Variable) {
	p.tailCall(ctx, mapName, 0, value, ret)
}

// MapLookup looks up a value in a map
func (p *ProgramBuilder) MapLookup(mapName string, key *Variable, value *Variable) {
	key.ptrReg(asm.R2)

	// be sure that R1 is not used by a ctx variable
	p.invalidateReg(asm.R1)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapLookupElem)...)

	value.setReg(asm.R0)
}

// MapLookupFD looks up a value in a map with a file descriptor
func (p *ProgramBuilder) MapLookupFD(fd int, key *Variable, value *Variable) {
	key.ptrReg(asm.R2)

	// be sure that R1 is not used by a ctx variable
	p.invalidateReg(asm.R1)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, fd),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapLookupElem)...)

	value.setReg(asm.R0)
}

// MapUpdate updates a value in a map
func (p *ProgramBuilder) MapUpdate(mapName string, key *Variable, value *Variable, ret *Variable, kind MapUpdateType) {
	key.ptrReg(asm.R2)
	value.ptrReg(asm.R3)

	// be sure that R1 is not used by a ctx variable
	p.invalidateReg(asm.R1)

	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R4, int32(kind)),
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapUpdateElem)...)

	if ret != nil {
		ret.setReg(asm.R0)
	}
}

// MapDelete deletes a value in a map
func (p *ProgramBuilder) MapDelete(mapName string, key *Variable, ret *Variable) {
	key.ptrReg(asm.R2)

	// be sure that R1 is not used by a ctx variable
	p.invalidateReg(asm.R1)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapDeleteElem)...)

	if ret != nil {
		ret.setReg(asm.R0)
	}
}

func (p *ProgramBuilder) lastInstIdx() int {
	return len(p.insts) - 1
}

func (p *ProgramBuilder) updateLastInstSymbol(symbol string) {
	p.insts[p.lastInstIdx()] = p.insts[p.lastInstIdx()].WithSymbol(symbol)
}

// If executes a condition and then
func (p *ProgramBuilder) IfThen(cond Condition, then func()) {
	p.IfThenElse(cond, then, nil)
}

// IfThenElse executes a condition and then or else
func (p *ProgramBuilder) IfThenElse(cond Condition, then func(), els func()) {
	var (
		jsg               = p.jmpSymGen.enterBlock()
		endifSym, elseSym = jsg.getSymbol("endif"), jsg.getSymbol("else")
		trueSym, falseSym = jsg.getSymbol("then"), endifSym
	)

	if els != nil {
		falseSym = elseSym
	}

	// first invalidate R0
	p.invalidateReg(asm.R0)

	// insert condition instructions
	cond(trueSym, falseSym)

	p.updateLastInstSymbol(trueSym)

	if then != nil {
		then()
	}

	p.insts = append(p.insts,
		asm.Ja.Label(endifSym).WithSymbol(elseSym),
	)

	if els != nil {
		els()
	}
	p.updateLastInstSymbol(endifSym)
}

func (p *ProgramBuilder) onRegExausted() {
	for _, vr := range p.variables {
		if vr.inReg() && isVarReg(vr.reg) && !vr.IsCtx() {
			vr.persist()
			return
		}
	}
}

// NewNumberVar creates a new number variable
func (p *ProgramBuilder) NewNumberVar(kind VariableType, value int64) *Variable {
	variable := newVariable(kind, math.MaxInt16, RNULL, p)

	regValue, err := p.regAlloc.Alloc()
	if err != nil {
		p.setError(err)
	}
	variable.reg = regValue

	switch kind {
	case Int64Type, UInt64Type:
		p.insts = append(p.insts,
			asm.LoadImm(regValue, value, asm.DWord),
		)
	default:
		p.insts = append(p.insts,
			asm.Mov.Imm(regValue, int32(value)),
		)
	}
	p.variables = append(p.variables, variable)

	return variable
}

// NewByteArrayVar creates a new byte array variable
func (p *ProgramBuilder) NewByteArrayVar(value []byte) *Variable {
	addr, insts := p.stackBytes(value)
	p.insts = append(p.insts, insts...)

	variable := newVariable(PtrType, math.MaxInt16, RNULL, p)

	regValue, err := p.regAlloc.Alloc()
	if err != nil {
		p.setError(err)
	}
	variable.reg = regValue

	p.insts = append(p.insts,
		asm.Mov.Reg(regValue, asm.RFP),
		asm.Add.Imm(regValue, int32(addr)),
	)

	p.variables = append(p.variables, variable)

	return variable
}

// NewPtrVar creates a new pointer variable
func (p *ProgramBuilder) NewPtrVar() *Variable {
	variable := newVariable(PtrType, math.MaxInt16, RNULL, p)

	regValue, err := p.regAlloc.Alloc()
	if err != nil {
		p.setError(err)
	}
	variable.reg = regValue

	p.variables = append(p.variables, variable)

	return variable
}

// NewCtxVar creates a new context variable
func (p *ProgramBuilder) NewCtxVar() *Variable {
	// be sure that R1 is not used by another ctx variable
	p.invalidateReg(asm.R1)

	variable := newVariable(CtxType, math.MaxInt16, asm.R1, p)

	p.variables = append(p.variables, variable)

	return variable
}

// newVarReg creates a new variable backed by a register
func (p *ProgramBuilder) newVarReg(kind VariableType) (*Variable, asm.Register) {
	reg, err := p.regAlloc.Alloc()
	if err != nil {
		p.setError(err)
	}

	variable := newVariable(kind, math.MaxInt16, reg, p)
	p.variables = append(p.variables, variable)

	return variable, reg
}

// NewVar creates a new variable
func (p *ProgramBuilder) NewVar(kind VariableType) *Variable {
	switch t := kind; t {
	case Int8Type, UInt8Type, Int16Type, UInt16Type, Int32Type, UInt32Type, Int64Type, UInt64Type:
		return p.NewNumberVar(t, 0)
	case PtrType:
		return p.NewPtrVar()
	}

	p.setError("variable type unknown")

	return newVariable(Int8Type, math.MaxInt16, RNULL, p)
}

// NewVarV creates a new variable from a value
func (p *ProgramBuilder) NewVarV(value interface{}) *Variable {
	switch v := value.(type) {
	case int8:
		return p.NewNumberVar(Int8Type, int64(v))
	case uint8:
		return p.NewNumberVar(UInt8Type, int64(v))
	case int16:
		return p.NewNumberVar(Int16Type, int64(v))
	case uint16:
		return p.NewNumberVar(UInt16Type, int64(v))
	case int32:
		return p.NewNumberVar(Int32Type, int64(v))
	case uint32:
		return p.NewNumberVar(UInt32Type, int64(v))
	case int64:
		return p.NewNumberVar(Int64Type, v)
	case uint64:
		return p.NewNumberVar(UInt64Type, int64(v))
	case []byte:
		return p.NewByteArrayVar(v)
	case string:
		return p.NewByteArrayVar([]byte(v))
	}

	p.setError("variable type unknown")

	return newVariable(Int8Type, math.MaxInt16, RNULL, p)
}

// FreeVar frees a variable
func (p *ProgramBuilder) FreeVar(v *Variable) {
	p.stackFree(v.addr)
	p.regAlloc.Free(v.reg)

	p.variables = slices.DeleteFunc(p.variables, func(o *Variable) bool {
		return v == o
	})
}
