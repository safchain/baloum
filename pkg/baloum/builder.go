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
)

type BuilderError struct {
	err        error
	stacktrace []byte
}

func NewBuilderError(err error) *BuilderError {
	p := &BuilderError{
		err: err,
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
	pb   *ProgramBuilder
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

func (vr *Variable) Deref(vt VariableType, offset int) *Variable {
	if !vr.IsPtr() {
		vr.pb.setError("invalid variable type")
	}

	derefVar := vr.pb.NewVar(vt)

	reg1, reg2, err := vr.pb.regAlloc.Alloc2()
	if err != nil {
		vr.pb.setError(err)
	}
	defer vr.pb.regAlloc.Free(reg1, reg2)

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.LoadMem(reg1, asm.RFP, vr.addr, vr.AsmSizeof()),
		asm.LoadMem(reg2, reg1, int16(offset), derefVar.AsmSizeof()),
		asm.StoreMem(asm.RFP, derefVar.addr, reg2, derefVar.AsmSizeof()),
	}...)

	return derefVar
}

func (vr *Variable) Ptr() asm.Register {
	reg, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		vr.pb.setError(err)
	}
	vr.PtrReg(reg)

	return reg
}

func (vr *Variable) PtrReg(reg asm.Register) {
	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.Mov.Reg(reg, asm.RFP),
		asm.Add.Imm(reg, int32(vr.addr)),
	}...)
}

func (vr *Variable) load(offset int) asm.Register {
	regVal, err := vr.pb.regAlloc.Alloc()
	if err != nil {
		vr.pb.setError(err)
	}

	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.LoadMem(regVal, asm.RFP, vr.addr+int16(offset), vr.AsmSizeof()),
	}...)

	return regVal
}

func (vr *Variable) store(reg asm.Register) {
	vr.pb.insts = append(vr.pb.insts, asm.Instructions{
		asm.StoreMem(asm.RFP, int16(vr.addr), reg, asm.DWord),
	}...)
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
}

func NewProgramBuilder(p *Program, opts ProgramBuilderOpts) *ProgramBuilder {
	opts.applyDefault()

	return &ProgramBuilder{
		program:  p,
		opts:     opts,
		regAlloc: NewRegisterAllocator(),
	}
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

func (p *ProgramBuilder) Commit() error {
	// relocate symbol
	for i := len(p.insts) - 1; i > 0; i-- {
		if symbol := p.insts[i-1].Symbol(); strings.HasSuffix(symbol, JumpSymbolType) {
			p.insts[i] = p.insts[i].WithSymbol(symbol)
			p.insts[i-1] = p.insts[i-1].WithSymbol("")
		}
	}
	p.program.insts = append(p.program.insts, p.insts...)

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
			if arg.IsPtr() {
				p.insts = append(p.insts,
					asm.Mov.Reg(reg, asm.RFP),
					asm.Add.Imm(reg, int32(arg.addr)),
				)
			} else {
				p.insts = append(p.insts,
					asm.LoadMem(reg, asm.RFP, arg.addr, arg.AsmSizeof()),
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
			p.setError(err)
		}
	}

	p.insts = append(p.insts,
		asm.FnTracePrintk.Call(),
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
			regPtr = var1.Ptr()
			regVal asm.Register
			err    error
		)
		defer p.regAlloc.Free(regPtr, regVal)

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
		defer p.regAlloc.Free(regPtr1, regVal1, regPtr2, regVal2)

		regPtr1, regPtr2 = var1.Ptr(), var2.Ptr()

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
	fnc := p.Equal(var1, var2)
	return func(trueSym, falseSym string) {
		fnc(falseSym, trueSym)
	}
}

func (p *ProgramBuilder) Equal(var1 *Variable, var2 interface{}) Condition {
	return func(trueSym string, falseSym string) {
		var (
			regVal1 = var1.load(0)
			regVal2 asm.Register
		)
		defer p.regAlloc.Free(regVal1, regVal2)

		switch v2 := var2.(type) {
		case *Variable:
			regVal2 = v2.load(0)

			p.insts = append(p.insts,
				asm.JEq.Reg(regVal1, regVal2, trueSym),
				asm.Ja.Label(falseSym),
			)
		case int8, uint8, int16, uint16, int32, uint32:
			val2, err := ToInt32(v2)
			if err != nil {
				p.setError(err)
			}

			p.insts = append(p.insts,
				asm.JEq.Imm(regVal1, val2, trueSym),
				asm.Ja.Label(falseSym),
			)
		case int64, uint64:
			val2, err := ToInt64(v2)
			if err != nil {
				p.setError(err)
			}

			p.insts = append(p.insts,
				asm.LoadImm(regVal2, val2, asm.DWord),
				asm.JEq.Reg(regVal1, regVal2, trueSym),
				asm.Ja.Label(falseSym),
			)
		default:
			p.setError("unknown type")
		}
	}
}

/*func (p *ProgramBuilder) TailCall(mapName string, key *Variable, value *Variable) error {
	if !value.IsPtr() {
		return errors.New("value is not a pointer type")
	}

	key.PtrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
		asm.FnMapLookupElem.Call(),
	)

	return value.Store(asm.R0)
}*/

func (p *ProgramBuilder) MapLookup(mapName string, key *Variable, value *Variable) {
	if !value.IsPtr() {
		p.setError("value is not a pointer type")
	}

	key.PtrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
		asm.FnMapLookupElem.Call(),
	)

	value.store(asm.R0)
}

func (p *ProgramBuilder) MapUpdate(mapName string, key *Variable, value *Variable, ret *Variable, kind MapUpdateType) {
	key.PtrReg(asm.R2)
	value.PtrReg(asm.R3)

	p.insts = append(p.insts,
		asm.Mov.Imm(asm.R4, int32(kind)),
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
		asm.FnMapUpdateElem.Call(),
	)

	if ret != nil {
		ret.store(asm.R0)
	}
}

func (p *ProgramBuilder) MapDelete(mapName string, key *Variable, ret *Variable) {
	key.PtrReg(asm.R2)

	p.insts = append(p.insts,
		asm.LoadMapPtr(asm.R1, 0).WithReference(mapName),
		asm.FnMapDeleteElem.Call(),
	)

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
		sbg = p.jmpSymGen.EnterBlock()

		trueSym  = sbg.GetSymbol("then")
		falseSym = sbg.GetSymbol("endif")
	)

	if els != nil {
		falseSym = sbg.GetSymbol("else")
	}

	cond(trueSym, falseSym)

	p.updateLastInstSymbol(trueSym)

	if then != nil {
		then()
	}

	p.insts = append(p.insts,
		asm.Ja.Label(sbg.GetSymbol("endif")).WithSymbol(sbg.GetSymbol("else")),
	)

	if els != nil {
		els()
	}
	p.updateLastInstSymbol(sbg.GetSymbol("endif"))
}

func (p *ProgramBuilder) NewNumberVar(kind VariableType, value int64) *Variable {
	addr := p.stackAlloc(int16(asm.DWord.Sizeof()))
	variable := &Variable{Type: kind, addr: addr, pb: p}

	regValue, err := p.regAlloc.Alloc()
	if err != nil {
		p.setError(err)
	}
	defer p.regAlloc.Free(regValue)

	switch kind {
	case Int64Type, UInt64Type:
		p.insts = append(p.insts,
			asm.LoadImm(regValue, value, asm.DWord),
			asm.StoreMem(asm.RFP, addr, regValue, asm.DWord),
		)
	default:
		p.insts = append(p.insts,
			asm.Mov.Imm(regValue, int32(value)),
			asm.StoreMem(asm.RFP, addr, regValue, asm.DWord),
		)
	}

	return variable
}

func (p *ProgramBuilder) NewByteArrayVar(value []byte) *Variable {
	addr, insts := p.stackBytes(value)
	variable := &Variable{Type: PtrType, addr: addr, pb: p}
	p.insts = append(p.insts, insts...)

	return variable
}

func (p *ProgramBuilder) NewPtrVar() *Variable {
	addr := p.stackAlloc(int16(asm.DWord.Sizeof()))
	return &Variable{Type: PtrType, addr: addr, pb: p}
}

func (p *ProgramBuilder) NewVar(kind VariableType) *Variable {
	switch t := kind; t {
	case Int8Type, UInt8Type, Int16Type, UInt16Type, Int32Type, UInt32Type, Int64Type, UInt64Type:
		return p.NewNumberVar(t, 0)
	case PtrType:
		return p.NewByteArrayVar(nil)
	}

	p.setError("variable type unknown")

	return &Variable{}
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

	return &Variable{}
}

func (p *ProgramBuilder) FreeVar() {
	// TODO(safchain) think of ptr
}
