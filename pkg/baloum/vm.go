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
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	ErrorCode = int(-1)
)

type vmState struct {
	regs  Regs
	stack []byte
}

type VM struct {
	Spec  *ebpf.CollectionSpec
	Opts  Opts
	stack []byte
	heap  *Heap
	regs  Regs
	fncs  map[asm.BuiltinFunc]func(*VM, *asm.Instruction) error
	strs  map[string]uint64
	maps  *MapCollection
}

func NewVM(spec *ebpf.CollectionSpec, opts Opts) *VM {
	opts.applyDefault()

	vm := &VM{
		Spec:  spec,
		Opts:  opts,
		stack: make([]byte, opts.StackSize),
		heap:  NewHeap(),
		strs:  make(map[string]uint64),
	}

	vm.maps = NewMapCollection(vm)

	vm.initStrs()
	vm.initFncs()

	return vm
}

func (vm *VM) saveState() *vmState {
	stack := make([]byte, vm.Opts.StackSize)
	copy(stack, vm.stack)

	return &vmState{
		stack: stack,
		regs:  vm.regs,
	}
}

func (vm *VM) loadState(state *vmState) {
	vm.stack = state.stack
	vm.regs = state.regs
}

func (vm *VM) Map(name string) *Map {
	return vm.maps.mapByName[name]
}

func (vm *VM) Heap() *Heap {
	return vm.heap
}

func (vm *VM) getMem(addr uint64) ([]byte, uint64, error) {
	// stack
	if addr&HEAP_ADDR_MASK == 0 {
		return vm.stack, addr & ADDR_MASK, nil
	}

	// heap block
	return vm.heap.GetMem(addr)
}

func (vm *VM) getBytes(addr uint64, size uint64) ([]byte, error) {
	bytes, addr, err := vm.getMem(addr)
	if err != nil {
		return nil, err
	}

	if size == 0 {
		return bytes[addr:], nil
	}

	if int(size) > len(bytes[addr:]) {
		return nil, errors.New("out of bound")
	}

	return bytes[addr : addr+size], nil
}

func (vm *VM) getUint64(addr uint64) (uint64, error) {
	bytes, err := vm.getBytes(addr, 8)
	if err != nil {
		return 0, err
	}

	return ByteOrder.Uint64(bytes), nil
}

func (vm *VM) getUint32(addr uint64) (uint32, error) {
	bytes, err := vm.getBytes(addr, 4)
	if err != nil {
		return 0, err
	}

	return ByteOrder.Uint32(bytes), nil
}

func (vm *VM) getUint16(addr uint64) (uint16, error) {
	bytes, err := vm.getBytes(addr, 2)
	if err != nil {
		return 0, err
	}

	return ByteOrder.Uint16(bytes), nil
}

func (vm *VM) getString(addr uint64) (string, error) {
	data, addr, err := vm.getMem(addr)
	if err != nil {
		return "", err
	}

	return Bytes2String(data[addr:]), nil
}

func (vm *VM) setUint64(addr uint64, value uint64) error {
	bytes, err := vm.getBytes(addr, 8)
	if err != nil {
		return err
	}
	ByteOrder.PutUint64(bytes, value)

	return nil
}

func (vm *VM) setUint32(addr uint64, value uint32) error {
	bytes, err := vm.getBytes(addr, 4)
	if err != nil {
		return err
	}
	ByteOrder.PutUint32(bytes, value)

	return nil
}

func (vm *VM) setUint16(addr uint64, value uint16) error {
	bytes, err := vm.getBytes(addr, 2)
	if err != nil {
		return err
	}

	ByteOrder.PutUint16(bytes, value)

	return nil
}

func (vm *VM) setUint8(addr uint64, value uint8) error {
	bytes, err := vm.getBytes(addr, 1)
	if err != nil {
		return err
	}

	bytes[0] = value

	return nil
}

func (vm *VM) addUint64(addr uint64, inc uint64) error {
	value, err := vm.getUint64(addr)
	if err != nil {
		return err
	}
	return vm.setUint64(addr, value+inc)
}

func isStrSection(name string) bool {
	return strings.HasPrefix(name, "rodatastr") || strings.HasPrefix(name, ".rodata.str")
}

func secStrNameKey(name string, offset uint64) string {
	return fmt.Sprintf("%s.%d", name, offset)
}

func (vm *VM) getStringAddr(name string, offset uint64) (uint64, error) {
	// normalize
	name = strings.Replace(name, ".", "", -1)
	key := secStrNameKey(name, offset)

	addr, exists := vm.strs[key]
	if !exists {
		return 0, fmt.Errorf("string not found: %s", name)
	}
	return addr, nil
}

func (vm *VM) initStrs() {
	for _, m := range vm.Spec.Maps {
		if isStrSection(m.Name) {
			for _, content := range m.Contents {
				var offset int
				for _, s := range bytes.Split(content.Value.([]byte), []byte{0}) {
					if len(s) == 0 {
						continue
					}

					key := fmt.Sprintf("%s.%d", m.Name, offset)
					vm.strs[key] = vm.heap.AllocWith(s)

					offset += len(s) + 1 // \0
				}
			}
		}
	}
}

func (vm *VM) initFncs() {
	vm.fncs = builtInFunc

	// override with RawFncs
	if vm.Opts.RawFncs != nil {
		for num, fncs := range vm.Opts.RawFncs {
			vm.fncs[num] = fncs
		}
	}
}

func getNormalizedInsts(prog *ebpf.ProgramSpec) []asm.Instruction {
	var insts []asm.Instruction

	for _, inst := range prog.Instructions {
		insts = append(insts, inst)
		if inst.Size() > 8 {
			// add a placeholder nop instruction
			insts = append(insts, asm.Instruction{})
		}
	}

	return insts
}

func (vm *VM) RunProgram(ctx Context, section string) (int, error) {
	var prog *ebpf.ProgramSpec
	for _, p := range vm.Spec.Programs {
		if progMatch(p, section) {
			prog = p
			break
		}
	}

	if prog == nil {
		return ErrorCode, fmt.Errorf("program not found: %s", section)
	}

	state := vm.saveState()
	defer func() {
		vm.loadState(state)
	}()

	// new state
	vm.stack = make([]byte, vm.Opts.StackSize)
	vm.regs[asm.RFP] = uint64(len(vm.stack))
	vm.regs[asm.R1] = vm.heap.AllocWith(ctx.Bytes())

	if err := vm.maps.LoadMaps(vm.Spec, section); err != nil {
		return ErrorCode, err
	}

	insts := getNormalizedInsts(prog)

	var pc int
	for pc != len(insts) {
		inst := insts[pc]

		vm.Opts.Logger.Debugf("%d > %v (%d)", pc, inst, inst.Size())
		pc += int(inst.Size() / 8)

		switch inst.OpCode {
		//
		case asm.LoadMemOp(asm.DWord):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.getUint64(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = value
		case asm.LoadMemOp(asm.Word):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.getUint32(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = uint64(value)
		case asm.LoadMemOp(asm.Half):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.getUint16(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = uint64(value)

		//
		case asm.LoadImmOp(asm.DWord):
			if inst.Src == asm.PseudoMapFD {
				_map := vm.maps.GetMapByName(inst.Reference())
				if _map == nil {
					return -1, fmt.Errorf("map not found: %v", inst.Reference())
				}
				vm.regs[inst.Dst] = uint64(_map.ID())
			} else if isStrSection(inst.Reference()) {
				offset := uint64(inst.Constant) >> 32
				addr, err := vm.getStringAddr(inst.Reference(), offset)
				if err != nil {
					return ErrorCode, err
				}
				vm.regs[inst.Dst] = addr
			} else {
				vm.regs[inst.Dst] = uint64(inst.Constant)
			}

		//
		case asm.LSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] <<= uint64(inst.Constant)
		case asm.LSh.Op(asm.RegSource):
			vm.regs[inst.Dst] <<= uint64(vm.regs[inst.Src])
		case asm.LSh.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) << uint32(inst.Constant))
		case asm.LSh.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) << uint32(vm.regs[inst.Src]))
		case asm.RSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] >>= uint64(inst.Constant)
		case asm.RSh.Op(asm.RegSource):
			vm.regs[inst.Dst] >>= uint64(vm.regs[inst.Src])
		case asm.RSh.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) >> uint32(inst.Constant))
		case asm.RSh.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) >> uint32(vm.regs[inst.Src]))
		case asm.ArSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(int64(vm.regs[inst.Dst]) >> uint64(inst.Constant))
		case asm.ArSh.Op(asm.RegSource):
			vm.regs[inst.Dst] = uint64(int64(vm.regs[inst.Dst]) >> uint64(vm.regs[inst.Src]))
		case asm.ArSh.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = zeroExtend(int32(vm.regs[inst.Dst]) >> uint32(inst.Constant))
		case asm.ArSh.Op32(asm.RegSource):
			vm.regs[inst.Dst] = zeroExtend(int32(vm.regs[inst.Dst]) >> uint32(vm.regs[inst.Src]))

		//
		case asm.StoreMemOp(asm.DWord):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.setUint64(dstAddr, vm.regs[inst.Src]); err != nil {
				return ErrorCode, err
			}
		case asm.StoreMemOp(asm.Word):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.setUint32(dstAddr, uint32(vm.regs[inst.Src])); err != nil {
				return ErrorCode, err
			}
		case asm.StoreMemOp(asm.Half):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.setUint16(dstAddr, uint16(vm.regs[inst.Src])); err != nil {
				return ErrorCode, err
			}
		case asm.StoreMemOp(asm.Byte):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.setUint8(dstAddr, uint8(vm.regs[inst.Src])); err != nil {
				return ErrorCode, err
			}

		//
		case asm.StoreXAddOp(asm.DWord):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.addUint64(dstAddr, vm.regs[inst.Src]); err != nil {
				return ErrorCode, err
			}

		//
		case asm.Mov.Op(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(inst.Constant)
		case asm.Mov.Op(asm.RegSource):
			vm.regs[inst.Dst] = vm.regs[inst.Src]
		case asm.Mov.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = zeroExtend(int32(inst.Constant))
		case asm.Mov.Op32(asm.RegSource):
			vm.regs[inst.Dst] = zeroExtend(int32(vm.regs[inst.Src]))

		//
		case asm.Add.Op(asm.ImmSource):
			vm.regs[inst.Dst] += uint64(inst.Constant)
		case asm.Add.Op(asm.RegSource):
			vm.regs[inst.Dst] += vm.regs[inst.Src]
		case asm.Add.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) + uint32(inst.Constant))
		case asm.Add.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) + uint32(vm.regs[inst.Src]))
		case asm.Sub.Op(asm.ImmSource):
			vm.regs[inst.Dst] -= uint64(inst.Constant)
		case asm.Sub.Op(asm.RegSource):
			vm.regs[inst.Dst] -= vm.regs[inst.Src]
		case asm.Sub.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) - uint32(inst.Constant))
		case asm.Sub.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) - uint32(vm.regs[inst.Src]))
		case asm.Mul.Op(asm.ImmSource):
			vm.regs[inst.Dst] *= uint64(inst.Constant)
		case asm.Mul.Op(asm.RegSource):
			vm.regs[inst.Dst] *= vm.regs[inst.Src]
		case asm.Mul.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) * uint32(inst.Constant))
		case asm.Mul.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) * uint32(vm.regs[inst.Src]))
		case asm.Div.Op(asm.ImmSource):
			if uint64(inst.Constant) == 0 {
				vm.regs[inst.Dst] = 0
			} else {
				vm.regs[inst.Dst] /= uint64(inst.Constant)
			}
		case asm.Div.Op(asm.RegSource):
			if uint64(vm.regs[inst.Src]) == 0 {
				vm.regs[inst.Dst] = 0
			} else {
				vm.regs[inst.Dst] /= vm.regs[inst.Src]
			}
		case asm.Div.Op32(asm.ImmSource):
			if uint32(inst.Constant) == 0 {
				vm.regs[inst.Dst] = 0
			} else {
				vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) / uint32(inst.Constant))
			}
		case asm.Div.Op32(asm.RegSource):
			if uint32(vm.regs[inst.Src]) == 0 {
				vm.regs[inst.Dst] = 0
			} else {
				vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) / uint32(vm.regs[inst.Src]))
			}
		case asm.And.Op(asm.ImmSource):
			vm.regs[inst.Dst] &= uint64(inst.Constant)
		case asm.And.Op(asm.RegSource):
			vm.regs[inst.Dst] &= vm.regs[inst.Src]
		case asm.And.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) & uint32(inst.Constant))
		case asm.And.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) & uint32(vm.regs[inst.Src]))
		case asm.Or.Op(asm.ImmSource):
			vm.regs[inst.Dst] |= uint64(inst.Constant)
		case asm.Or.Op(asm.RegSource):
			vm.regs[inst.Dst] |= vm.regs[inst.Src]
		case asm.Or.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) | uint32(inst.Constant))
		case asm.Or.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) | uint32(vm.regs[inst.Src]))
		case asm.Xor.Op(asm.ImmSource):
			vm.regs[inst.Dst] ^= uint64(inst.Constant)
		case asm.Xor.Op(asm.RegSource):
			vm.regs[inst.Dst] ^= vm.regs[inst.Src]
		case asm.Xor.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) ^ uint32(inst.Constant))
		case asm.Xor.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) ^ uint32(vm.regs[inst.Src]))

		//
		case asm.Ja.Op(asm.ImmSource):
			pc += int(inst.Offset)
		case asm.Ja.Op(asm.RegSource):
			pc += int(vm.regs[inst.Src])
		case asm.JEq.Op(asm.ImmSource):
			if vm.regs[inst.Dst] == uint64(inst.Constant) {
				pc += int(inst.Offset)
			}
		case asm.JEq.Op(asm.RegSource):
			if vm.regs[inst.Dst] == vm.regs[inst.Src] {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JEq, asm.ImmSource):
			if uint32(vm.regs[inst.Dst]) == uint32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JEq, asm.RegSource):
			if uint32(vm.regs[inst.Dst]) == uint32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JSet.Op(asm.ImmSource):
			if (vm.regs[inst.Dst] & uint64(inst.Constant)) != 0 {
				pc += int(inst.Offset)
			}
		case asm.JSet.Op(asm.RegSource):
			if (vm.regs[inst.Dst] & vm.regs[inst.Src]) != 0 {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSet, asm.ImmSource):
			if (uint32(vm.regs[inst.Dst]) & uint32(inst.Constant)) != 0 {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSet, asm.RegSource):
			if (uint32(vm.regs[inst.Dst]) & uint32(vm.regs[inst.Src])) != 0 {
				pc += int(inst.Offset)
			}
		case asm.JNE.Op(asm.ImmSource):
			if vm.regs[inst.Dst] != uint64(inst.Constant) {
				pc += int(inst.Offset)
			}
		case asm.JNE.Op(asm.RegSource):
			if vm.regs[inst.Dst] != vm.regs[inst.Src] {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JNE, asm.ImmSource):
			if uint32(vm.regs[inst.Dst]) != uint32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JNE, asm.RegSource):
			if uint32(vm.regs[inst.Dst]) != uint32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JGE.Op(asm.RegSource):
			if vm.regs[inst.Dst] >= vm.regs[inst.Src] {
				pc += int(inst.Offset)
			}
		case asm.JGE.Op(asm.ImmSource):
			if vm.regs[inst.Dst] >= uint64(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JGE, asm.ImmSource):
			if uint32(vm.regs[inst.Dst]) >= uint32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JGE, asm.RegSource):
			if uint32(vm.regs[inst.Dst]) >= uint32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JGT.Op(asm.RegSource):
			if vm.regs[inst.Dst] > vm.regs[inst.Src] {
				pc += int(inst.Offset)
			}
		case asm.JGT.Op(asm.ImmSource):
			if vm.regs[inst.Dst] > uint64(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JGT, asm.ImmSource):
			if uint32(vm.regs[inst.Dst]) > uint32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JGT, asm.RegSource):
			if uint32(vm.regs[inst.Dst]) > uint32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JLE.Op(asm.RegSource):
			if vm.regs[inst.Dst] <= vm.regs[inst.Src] {
				pc += int(inst.Offset)
			}
		case asm.JLE.Op(asm.ImmSource):
			if vm.regs[inst.Dst] <= uint64(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JLE, asm.ImmSource):
			if uint32(vm.regs[inst.Dst]) <= uint32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JLE, asm.RegSource):
			if uint32(vm.regs[inst.Dst]) <= uint32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JLT.Op(asm.RegSource):
			if vm.regs[inst.Dst] < vm.regs[inst.Src] {
				pc += int(inst.Offset)
			}
		case asm.JLT.Op(asm.ImmSource):
			if vm.regs[inst.Dst] < uint64(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JLT, asm.ImmSource):
			if uint32(vm.regs[inst.Dst]) < uint32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JLT, asm.RegSource):
			if uint32(vm.regs[inst.Dst]) < uint32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}

		//
		case asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call):
			if fnc := vm.fncs[asm.BuiltinFunc(inst.Constant)]; fnc != nil {
				if err := fnc(vm, &inst); err != nil {
					return ErrorCode, err
				}
			} else {
				return ErrorCode, fmt.Errorf("unknown function: %v", inst)
			}

		//
		case asm.Exit.Op(asm.ImmSource):
			return int(int32(vm.regs[asm.R0])), nil
		default:
			return ErrorCode, fmt.Errorf("unknown op: %v", inst)
		}
	}

	return ErrorCode, errors.New("unexpected error")
}

func zeroExtend(in int32) uint64 {
	return uint64(uint32(in))
}

func JumpOpCode(class asm.Class, jumpOp asm.JumpOp, source asm.Source) asm.OpCode {
	return asm.OpCode(class).SetJumpOp(jumpOp).SetSource(source)
}
