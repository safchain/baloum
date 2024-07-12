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
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"

	"github.com/cilium/ebpf/asm"
	"golang.org/x/exp/slices"
)

type BuilderError struct {
	err        error
	stacktrace []byte
}

func NewBuilderError(err error) *BuilderError {
	p := &BuilderError{
		err:        err,
		stacktrace: make([]byte, 4096),
	}
	runtime.Stack(p.stacktrace, false)
	return p
}

func (b *BuilderError) Error() string {
	return b.err.Error()
}

func (b *BuilderError) Stack() []byte {
	return b.stacktrace
}

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

func IsVarReg(reg asm.Register) bool {
	return reg >= asm.R6 && reg < asm.R10
}

type RegisterAllocator struct {
	available  []asm.Register
	onExausted func()
}

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
		if IsVarReg(reg) && reg != RNULL {
			r.available = append([]asm.Register{reg}, r.available...)
		}
	}
}

func NewRegisterAllocator(onExausted func()) *RegisterAllocator {
	r := RegisterAllocator{
		onExausted: onExausted,
	}

	for reg := asm.R6; reg != asm.R10; reg++ {
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
	PtrType
)

func (vt VariableType) IsPtr() bool {
	return vt == PtrType
}

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

func (vt VariableType) Sizeof() int {
	return vt.AsmSizeof().Sizeof()
}

type Variable struct {
	Type VariableType

	addr int16
	reg  asm.Register
	pb   *ProgramBuilder
}

func newVariable(kind VariableType, addr int16, reg asm.Register, pb *ProgramBuilder) *Variable {
	return &Variable{
		Type: kind,
		addr: addr,
		reg:  reg,
		pb:   pb,
	}
}

func (vr *Variable) IsPtr() bool {
	return vr.Type.IsPtr()
}

func (vr *Variable) AsmSizeof() asm.Size {
	return vr.Type.AsmSizeof()
}

func (vr *Variable) Sizeof() int {
	return vr.Type.Sizeof()
}

func (vr *Variable) InReg() bool {
	return vr.reg != RNULL
}

func (vr *Variable) Deref(vt VariableType, offset int) *Variable {
	if !vr.IsPtr() {
		vr.pb.setError("invalid variable type")
	}

	if !vr.InReg() {
		vr.load()
	}

	reg2, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		vr.pb.setError(err)
	}

	derefVar := vr.pb.newVarReg(vt, reg2)

	vr.pb.insts = append(vr.pb.insts,
		asm.LoadMem(reg2, vr.reg, int16(offset), derefVar.AsmSizeof()),
	)

	return derefVar
}

// PtrReg set reg to the address of the variable
func (vr *Variable) ptrReg(reg asm.Register) {
	vr.persist()

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.addr)),
	}...)
}

func (vr *Variable) load() asm.Register {
	if vr.InReg() {
		return vr.reg
	}

	regVal, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		vr.pb.setError(err)
	}

	vr.loadReg(regVal)

	return regVal
}

func (vr *Variable) loadReg(reg asm.Register) {
	if vr.InReg() {
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
	if IsVarReg(reg) {
		vr.store(reg)
	}
}

func (vr *Variable) store(reg asm.Register) {
	vr.pb.regAlloc.Free(vr.reg)
	vr.reg = reg
}

func (vr *Variable) persist() {
	if !vr.InReg() {
		return
	}

	if vr.addr == math.MaxInt16 {
		vr.addr = vr.pb.stackAlloc(int16(asm.DWord.Sizeof()))
	}

	vr.pb.insts = append(vr.pb.insts,
		asm.StoreMem(asm.RFP, int16(vr.addr), vr.reg, vr.AsmSizeof()),
	)

	vr.store(RNULL)
}

type JmpSymbolGenerator struct {
	idx int
}

type EnterJmpSymbolBlock struct {
	idx int
}

func (s *JmpSymbolGenerator) EnterBlock() *EnterJmpSymbolBlock {
	s.idx++
	return &EnterJmpSymbolBlock{idx: s.idx}
}

func (e *EnterJmpSymbolBlock) GetSymbol(prefix string) string {
	return fmt.Sprintf("%s-%d-%s", prefix, e.idx, JumpSymbolType)
}

type ProgramBuilderOpts struct {
	StackSize int
}

func (p *ProgramBuilderOpts) applyDefault() {
	if p.StackSize == 0 {
		p.StackSize = DEFAULT_STACK_SIZE
	}
}

type ProgramBuilder struct {
	program   *Program
	opts      ProgramBuilderOpts
	insts     asm.Instructions
	blocks    []stackMemBlock
	jmpSymGen JmpSymbolGenerator
	regAlloc  *RegisterAllocator
	err       error
	variables []*Variable
}

func NewProgramBuilder(p *Program, opts ProgramBuilderOpts) *ProgramBuilder {
	opts.applyDefault()

	pb := &ProgramBuilder{
		program: p,
		opts:    opts,
	}

	pb.regAlloc = NewRegisterAllocator(pb.onRegExausted)

	return pb
}

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

func (p *ProgramBuilder) swapReg(reg asm.Register) {
	for _, v := range p.variables {
		if v.InReg() && v.reg == reg {
			targetReg, err := p.regAlloc.Alloc()
			if err != nil {
				p.setError(err)
			}

			if targetReg != reg {
				p.insts = append(p.insts,
					asm.Mov.Reg(targetReg, reg),
				)

				v.store(targetReg)
			}

			break
		}
	}
}

func (p *ProgramBuilder) CallFn(fn asm.BuiltinFunc) asm.Instructions {
	// invalidate R0
	p.swapReg(asm.R0)

	return asm.Instructions{
		fn.Call(),
	}
}

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

	p.program.PrintInstructions()

	return p.err
}

func (p *ProgramBuilder) stackAlloc(size int16) int16 {
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

	addr := p.stackAlloc(int16(len(values) * 8))

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

	return addr, instructions
}

func (p *ProgramBuilder) Return(code int) {
	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R0, int32(code)),
		asm.Return(),
	)
}

func (p *ProgramBuilder) Printk(format string, args ...interface{}) {
	if len(args) > 3 {
		p.setError("maximum of args excedeed")
		args = args[0:3]
	}

	// format
	addr, insts := p.stackBytes([]byte(format))
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
			arg.loadReg(reg)
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

func (p *ProgramBuilder) StrIn(var1 *Variable, strs ...string) Condition {
	var conds []Condition
	for _, str := range strs {
		conds = append(conds, p.StrStaticCmp(var1, str))
	}
	return p.Or(conds...)
}

func (p *ProgramBuilder) True() Condition {
	return func(trueSym, falseSym string) {
		p.insts = append(p.insts,
			asm.Ja.Label(trueSym),
		)
	}
}

func (p *ProgramBuilder) False() Condition {
	return func(trueSym, falseSym string) {
		p.insts = append(p.insts,
			asm.Ja.Label(falseSym),
		)
	}
}

func (p *ProgramBuilder) And(conds ...Condition) Condition {
	return func(trueSym, falseSym string) {
		for i, cond := range conds {
			sbg := p.jmpSymGen.EnterBlock()

			if i == len(conds)-1 {
				cond(trueSym, falseSym)
			} else {
				nextCondSym := sbg.GetSymbol("next-cond")

				cond(nextCondSym, falseSym)
				p.updateLastInstSymbol(nextCondSym)
			}
		}
	}
}

func (p *ProgramBuilder) Or(conds ...Condition) Condition {
	return func(trueSym, falseSym string) {
		for i, cond := range conds {
			sbg := p.jmpSymGen.EnterBlock()

			if i == len(conds)-1 {
				cond(trueSym, falseSym)
			} else {
				nextCondSym := sbg.GetSymbol("next-cond")

				cond(trueSym, nextCondSym)
				p.updateLastInstSymbol(nextCondSym)
			}
		}
	}
}

func (p *ProgramBuilder) IsNull(var1 *Variable) Condition {
	return p.Equal(var1, uint32(0))
}

func (p *ProgramBuilder) IsNotNull(var1 *Variable) Condition {
	return p.NotEqual(var1, uint32(0))
}

func (p *ProgramBuilder) NotEqual(var1 *Variable, var2 interface{}) Condition {
	return p.Not(p.Equal(var1, var2))
}

func (p *ProgramBuilder) Not(cond Condition) Condition {
	return func(trueSym, falseSym string) {
		cond(falseSym, trueSym)
	}
}

func (p *ProgramBuilder) Equal(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JEq)
}

func (p *ProgramBuilder) Greater(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JGT)
}

func (p *ProgramBuilder) GreaterEqual(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JGE)
}

func (p *ProgramBuilder) Lesser(var1 *Variable, var2 interface{}) Condition {
	return p.cmp(var1, var2, asm.JLT)
}

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

func (p *ProgramBuilder) TailCall(mapName string, value interface{}, ret *Variable) {
	switch v := value.(type) {
	case *Variable:
		v.loadReg(asm.R3)
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
		asm.LoadMapPtr(asm.R2, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnTailCall)...)

	ret.store(asm.R0)
}

func (p *ProgramBuilder) MapLookup(mapName string, key *Variable, value *Variable) {
	key.ptrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapLookupElem)...)

	value.store(asm.R0)
}

func (p *ProgramBuilder) MapLookupFD(fd int, key *Variable, value *Variable) {
	key.ptrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, fd),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapLookupElem)...)

	value.store(asm.R0)
}

func (p *ProgramBuilder) MapUpdate(mapName string, key *Variable, value *Variable, ret *Variable, kind MapUpdateType) {
	key.ptrReg(asm.R2)
	value.ptrReg(asm.R3)

	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R4, int32(kind)),
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapUpdateElem)...)

	if ret != nil {
		ret.store(asm.R0)
	}
}

func (p *ProgramBuilder) MapDelete(mapName string, key *Variable, ret *Variable) {
	key.ptrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
	)
	p.insts = append(p.insts, p.CallFn(asm.FnMapDeleteElem)...)

	if ret != nil {
		ret.store(asm.R0)
	}
}

func (p *ProgramBuilder) lastInstIdx() int {
	return len(p.insts) - 1
}

func (p *ProgramBuilder) updateLastInstSymbol(symbol string) {
	p.insts[p.lastInstIdx()] = p.insts[p.lastInstIdx()].WithSymbol(symbol)
}

func (p *ProgramBuilder) IfThenElse(cond Condition, then func(), els func()) {
	var (
		jsg               = p.jmpSymGen.EnterBlock()
		endifSym, elseSym = jsg.GetSymbol("endif"), jsg.GetSymbol("else")
		trueSym, falseSym = jsg.GetSymbol("then"), endifSym
	)

	if els != nil {
		falseSym = elseSym
	}

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
		if vr.InReg() && IsVarReg(vr.reg) {
			vr.persist()
			return
		}
	}
}

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

func (p *ProgramBuilder) newVarReg(kind VariableType, reg asm.Register) *Variable {
	variable := newVariable(kind, math.MaxInt16, reg, p)

	p.variables = append(p.variables, variable)

	return variable
}

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

func (p *ProgramBuilder) FreeVar(v *Variable) {
	p.stackFree(v.addr)
	p.regAlloc.Free(v.reg)

	slices.DeleteFunc(p.variables, func(o *Variable) bool {
		return v == o
	})
}
