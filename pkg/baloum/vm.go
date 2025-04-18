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
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	ErrorCode = int64(-1)

	// bitmasks
	fetchBit = 0x01
)

type vmState struct {
	regs  Regs
	stack []byte
}

type program []asm.Instruction

type VM struct {
	Spec      *ebpf.CollectionSpec
	Opts      Opts
	stack     []byte
	heap      *Heap
	regs      Regs
	fncs      map[asm.BuiltinFunc]func(*VM, *asm.Instruction) error
	strs      map[string]uint64
	maps      *MapCollection
	programs  []*ebpf.ProgramSpec
	progType  ebpf.ProgramType
	ctx       Context
	tailCails int
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

func (vm *VM) GetBytes(addr uint64, size uint64) ([]byte, error) {
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

func (vm *VM) GetUint64(addr uint64) (uint64, error) {
	bytes, err := vm.GetBytes(addr, 8)
	if err != nil {
		return 0, err
	}

	return ByteOrder.Uint64(bytes), nil
}

func (vm *VM) GetUint32(addr uint64) (uint32, error) {
	bytes, err := vm.GetBytes(addr, 4)
	if err != nil {
		return 0, err
	}

	return ByteOrder.Uint32(bytes), nil
}

func (vm *VM) GetUint16(addr uint64) (uint16, error) {
	bytes, err := vm.GetBytes(addr, 2)
	if err != nil {
		return 0, err
	}

	return ByteOrder.Uint16(bytes), nil
}

func (vm *VM) GetUint8(addr uint64) (uint8, error) {
	bytes, err := vm.GetBytes(addr, 1)
	if err != nil {
		return 0, err
	}

	return uint8(bytes[0]), nil
}

func (vm *VM) GetString(addr uint64) (string, error) {
	data, addr, err := vm.getMem(addr)
	if err != nil {
		return "", err
	}

	return Bytes2String(data[addr:]), nil
}

func (vm *VM) SetUint64(addr uint64, value uint64) error {
	bytes, err := vm.GetBytes(addr, 8)
	if err != nil {
		return err
	}
	ByteOrder.PutUint64(bytes, value)

	return nil
}

func (vm *VM) SetUint32(addr uint64, value uint32) error {
	bytes, err := vm.GetBytes(addr, 4)
	if err != nil {
		return err
	}
	ByteOrder.PutUint32(bytes, value)

	return nil
}

func (vm *VM) SetUint16(addr uint64, value uint16) error {
	bytes, err := vm.GetBytes(addr, 2)
	if err != nil {
		return err
	}

	ByteOrder.PutUint16(bytes, value)

	return nil
}

func (vm *VM) SetUint8(addr uint64, value uint8) error {
	bytes, err := vm.GetBytes(addr, 1)
	if err != nil {
		return err
	}

	bytes[0] = value

	return nil
}

func (vm *VM) SetBytes(addr uint64, value []byte, size uint64) error {
	bytes, err := vm.GetBytes(addr, size)
	if err != nil {
		return err
	}

	if int(size) > len(bytes) {
		return errors.New("not enough space")
	}

	copy(bytes, value[:size])

	return nil
}

func (vm *VM) atomicUint64(addr uint64, inc uint64, imm int64) (uint64, bool, error) {
	value, err := vm.GetUint64(addr)
	if err != nil {
		return 0, false, err
	}
	var res uint64
	switch imm & 0xF0 {
	case 0x00: // ADD
		res = value + inc
	case 0x40: // OR
		res = value | inc
	case 0x50: // AND
		res = value & inc
	case 0xa0: // XOR
		res = value ^ inc
	case 0xe0: // XCHG
		res = inc
	case 0xf0: // CMPXCHG
		if value == vm.regs[asm.R0] {
			if err := vm.SetUint64(addr, inc); err != nil {
				return 0, false, err
			}
		}
		return value, true, nil
	default:
		return 0, false, fmt.Errorf("unknown atomic operand: %d", imm)
	}
	return value, false, vm.SetUint64(addr, res)
}

func (vm *VM) atomicUint32(addr uint64, inc uint32, imm int64) (uint32, bool, error) {
	value, err := vm.GetUint32(addr)
	if err != nil {
		return 0, false, err
	}
	var res uint32
	switch imm & 0xF0 {
	case 0x00: // ADD
		res = value + inc
	case 0x40: // OR
		res = value | inc
	case 0x50: // AND
		res = value & inc
	case 0xa0: // XOR
		res = value ^ inc
	case 0xe0: // XCHG
		res = inc
	case 0xf0: // CMPXCHG
		if value == uint32(vm.regs[asm.R0]) {
			if err := vm.SetUint32(addr, inc); err != nil {
				return 0, false, err
			}
		}
		return value, true, nil
	default:
		return 0, false, fmt.Errorf("unknown atomic operand: %d", imm)
	}
	return value, false, vm.SetUint32(addr, res)
}

func isStrSection(name string) bool {
	return (strings.HasPrefix(name, "rodata") ||
		strings.HasPrefix(name, ".rodata") ||
		strings.HasPrefix(name, "rodatastr") ||
		strings.HasPrefix(name, ".rodata.str"))
}

func secStrNameKey(name string, offset uint64) string {
	name = strings.Replace(name, ".", "", -1)
	return fmt.Sprintf("%s.%d", name, offset)
}

func (vm *VM) getStringAddr(name string, offset uint64) (uint64, error) {
	// normalize
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
				var data []byte
				var offset int

				for o, c := range content.Value.([]byte) {
					if c == 0x0 {
						if str := string(data); len(str) != 0 {
							key := secStrNameKey(m.Name, uint64(offset))
							vm.strs[key] = vm.heap.AllocWith([]byte(str))
						}

						data = data[:0]
						offset = o + 1
					} else {
						data = append(data, c)
					}
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

func resolveSymbolReferences(insts asm.Instructions) asm.Instructions {
	var resolved asm.Instructions

	symbols := make(map[string]int)

	for offset, ins := range insts {
		if symbol := ins.Symbol(); symbol != "" {
			symbols[symbol] = offset
		}
	}

	for i, inst := range insts {
		resolved = append(resolved, inst)

		if ref := inst.Reference(); ref != "" {
			offset, exists := symbols[ref]
			if exists {
				var inc int

				// correct with size of instruction size
				delta := offset - i - 1
				if delta > 0 {
					for j := 0; j != delta; j++ {
						if insts[i+j].Size() > 8 {
							inc++
						}
					}
				} else {
					for j := 0; j != delta; j-- {
						if insts[i+j].Size() > 8 {
							inc--
						}
					}
				}

				inst.Offset = int16(delta + inc)
				resolved[i] = inst
			}
		}
	}

	return resolved
}

func normalizeInsts(insts []asm.Instruction) []asm.Instruction {
	var normInsts []asm.Instruction

	for _, inst := range insts {
		normInsts = append(normInsts, inst)
		if inst.Size() > 8 {
			// add a placeholder nop instruction
			normInsts = append(normInsts, asm.Instruction{})
		}
	}

	return normInsts
}

// Regs returns vm registers
func (vm *VM) Regs() Regs {
	return vm.regs
}

// Stack returns the stack
func (vm *VM) Stack() []byte {
	return vm.stack
}

// GetMapByName returns the map
func (vm *VM) GetMapByName(name string) *Map {
	return vm.maps.GetMapByName(name)
}

func (vm *VM) RunInstructions(ctx Context, insts []asm.Instruction) (int64, error) {
	// prepare the instruction
	insts = resolveSymbolReferences(insts)
	insts = normalizeInsts(insts)

	state := vm.saveState()
	defer func() {
		vm.loadState(state)
	}()

	ctx.SetRegs(vm)

	// new state
	vm.stack = make([]byte, vm.Opts.StackSize)
	vm.regs[asm.RFP] = uint64(len(vm.stack))

	var pc int
	for pc != len(insts) {
		inst := insts[pc]

		if vm.Opts.Observer != nil {
			vm.Opts.Observer.ObserveInst(vm, pc, &inst)
		}

		vm.Opts.Logger.Debugf("%d > %v (%d)", pc, inst, inst.Size())
		pc += int(inst.Size() / 8)

		opcode := inst.OpCode
		switch opcode {
		//
		case asm.LoadMemOp(asm.DWord):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.GetUint64(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = value
		case asm.LoadMemOp(asm.Word):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.GetUint32(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = uint64(value)
		case asm.LoadMemOp(asm.Half):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.GetUint16(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = uint64(value)
		case asm.LoadMemOp(asm.Byte):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.GetUint8(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = uint64(value)

		//
		case asm.LoadImmOp(asm.DWord):
			if inst.Src == asm.PseudoMapFD {
				var _map *Map
				if ref := inst.Reference(); ref != "" {
					if _map = vm.maps.GetMapByName(inst.Reference()); _map == nil {
						return -1, fmt.Errorf("map not found: %v", inst.Reference())
					}
				} else if _map = vm.maps.GetMapById(int(inst.Constant)); _map == nil {
					return -1, fmt.Errorf("map not found: %v", inst.Src)
				}
				vm.regs[inst.Dst] = uint64(_map.id)
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
		case asm.LoadImmOp(asm.Word):
			vm.regs[inst.Dst] = uint64(inst.Constant)
		case asm.LoadImmOp(asm.Half):
			vm.regs[inst.Dst] = uint64(inst.Constant)
		case asm.LoadImmOp(asm.Byte):
			vm.regs[inst.Dst] = uint64(inst.Constant)

		//
		case asm.LSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] <<= uint64(uint64(inst.Constant) % 64)
		case asm.LSh.Op(asm.RegSource):
			vm.regs[inst.Dst] <<= uint64(vm.regs[inst.Src] % 64)
		case asm.LSh.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) << uint32(uint32(inst.Constant)%32))
		case asm.LSh.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) << uint32(vm.regs[inst.Src]%32))
		case asm.RSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] >>= uint64(uint64(inst.Constant) % 64)
		case asm.RSh.Op(asm.RegSource):
			vm.regs[inst.Dst] >>= uint64(vm.regs[inst.Src] % 64)
		case asm.RSh.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) >> uint32(uint32(inst.Constant)%32))
		case asm.RSh.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) >> uint32(vm.regs[inst.Src]%32))
		case asm.ArSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(int64(vm.regs[inst.Dst]) >> uint64(uint64(inst.Constant)%64))
		case asm.ArSh.Op(asm.RegSource):
			vm.regs[inst.Dst] = uint64(int64(vm.regs[inst.Dst]) >> uint64(vm.regs[inst.Src]%64))
		case asm.ArSh.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(uint32(int32(vm.regs[inst.Dst]) >> (uint32(inst.Constant) % 32)))
		case asm.ArSh.Op32(asm.RegSource):
			vm.regs[inst.Dst] = uint64(uint32(int32(vm.regs[inst.Dst]) >> (vm.regs[inst.Src] % 32)))

		//
		case asm.StoreMemOp(asm.DWord):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint64(dstAddr, vm.regs[inst.Src]); err != nil {
				return ErrorCode, err
			}
		case asm.StoreMemOp(asm.Word):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint32(dstAddr, uint32(vm.regs[inst.Src])); err != nil {
				return ErrorCode, err
			}
		case asm.StoreMemOp(asm.Half):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint16(dstAddr, uint16(vm.regs[inst.Src])); err != nil {
				return ErrorCode, err
			}
		case asm.StoreMemOp(asm.Byte):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint8(dstAddr, uint8(vm.regs[inst.Src])); err != nil {
				return ErrorCode, err
			}

		case asm.StoreImmOp(asm.DWord):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint64(dstAddr, uint64(inst.Constant)); err != nil {
				return ErrorCode, err
			}
		case asm.StoreImmOp(asm.Word):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint32(dstAddr, uint32(inst.Constant)); err != nil {
				return ErrorCode, err
			}
		case asm.StoreImmOp(asm.Half):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint16(dstAddr, uint16(inst.Constant)); err != nil {
				return ErrorCode, err
			}
		case asm.StoreImmOp(asm.Byte):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			if err := vm.SetUint8(dstAddr, uint8(inst.Constant)); err != nil {
				return ErrorCode, err
			}

		//
		case asm.StoreXAddOp(asm.DWord):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			oldValue, overrideSrcWithR0, err := vm.atomicUint64(dstAddr, vm.regs[inst.Src], inst.Constant)
			if err != nil {
				return ErrorCode, err
			}
			if inst.Constant&fetchBit != 0 {
				if overrideSrcWithR0 {
					vm.regs[asm.R0] = oldValue
				} else {
					vm.regs[inst.Src] = oldValue
				}
			}
		case asm.StoreXAddOp(asm.Word):
			dstAddr := vm.regs[inst.Dst] + uint64(inst.Offset)
			oldValue, overrideSrcWithR0, err := vm.atomicUint32(dstAddr, uint32(vm.regs[inst.Src]), inst.Constant)
			if err != nil {
				return ErrorCode, err
			}
			if inst.Constant&fetchBit != 0 {
				if overrideSrcWithR0 {
					vm.regs[asm.R0] = uint64(oldValue)
				} else {
					vm.regs[inst.Src] = uint64(oldValue)
				}
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
		case asm.Mod.Op(asm.ImmSource):
			if uint64(inst.Constant) == 0 {
				vm.regs[inst.Dst] = 1
			} else {
				vm.regs[inst.Dst] %= uint64(inst.Constant)
			}
		case asm.Mod.Op(asm.RegSource):
			if uint64(vm.regs[inst.Src]) == 0 {
				vm.regs[inst.Dst] = 1
			} else {
				vm.regs[inst.Dst] %= vm.regs[inst.Src]
			}
		case asm.Mod.Op32(asm.ImmSource):
			if uint32(inst.Constant) == 0 {
				vm.regs[inst.Dst] = 1
			} else {
				vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) % uint32(inst.Constant))
			}
		case asm.Mod.Op32(asm.RegSource):
			if uint32(vm.regs[inst.Src]) == 0 {
				vm.regs[inst.Dst] = 1
			} else {
				vm.regs[inst.Dst] = uint64(uint32(vm.regs[inst.Dst]) % uint32(vm.regs[inst.Src]))
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
		case asm.Neg.Op(asm.ImmSource):
			vm.regs[inst.Dst] = -vm.regs[inst.Src]
		case asm.Neg.Op32(asm.ImmSource):
			vm.regs[inst.Dst] = zeroExtend(-int32(vm.regs[inst.Src]))

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
		case asm.JSGE.Op(asm.RegSource):
			if int64(vm.regs[inst.Dst]) >= int64(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JSGE.Op(asm.ImmSource):
			if int64(vm.regs[inst.Dst]) >= inst.Constant {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSGE, asm.ImmSource):
			if int32(vm.regs[inst.Dst]) >= int32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSGE, asm.RegSource):
			if int32(vm.regs[inst.Dst]) >= int32(vm.regs[inst.Src]) {
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
		case asm.JSGT.Op(asm.RegSource):
			if int64(vm.regs[inst.Dst]) > int64(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JSGT.Op(asm.ImmSource):
			if int64(vm.regs[inst.Dst]) > inst.Constant {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSGT, asm.ImmSource):
			if int32(vm.regs[inst.Dst]) > int32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSGT, asm.RegSource):
			if int32(vm.regs[inst.Dst]) > int32(vm.regs[inst.Src]) {
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
		case asm.JSLE.Op(asm.RegSource):
			if int64(vm.regs[inst.Dst]) <= int64(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JSLE.Op(asm.ImmSource):
			if int64(vm.regs[inst.Dst]) <= inst.Constant {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSLE, asm.ImmSource):
			if int32(vm.regs[inst.Dst]) <= int32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSLE, asm.RegSource):
			if int32(vm.regs[inst.Dst]) <= int32(vm.regs[inst.Src]) {
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
		case asm.JSLT.Op(asm.RegSource):
			if int64(vm.regs[inst.Dst]) < int64(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}
		case asm.JSLT.Op(asm.ImmSource):
			if int64(vm.regs[inst.Dst]) < inst.Constant {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSLT, asm.ImmSource):
			if int32(vm.regs[inst.Dst]) < int32(inst.Constant) {
				pc += int(inst.Offset)
			}
		case JumpOpCode(asm.Jump32Class, asm.JSLT, asm.RegSource):
			if int32(vm.regs[inst.Dst]) < int32(vm.regs[inst.Src]) {
				pc += int(inst.Offset)
			}

		//
		case asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call):
			switch inst.Src {
			case 0:
				// helpers
				builtin := asm.BuiltinFunc(inst.Constant)
				if fnc := vm.fncs[builtin]; fnc != nil {
					if err := fnc(vm, &inst); err != nil {
						return ErrorCode, err
					}

					// if tail call endup here
					if builtin == asm.FnTailCall {
						return int64(int32(vm.regs[asm.R0])), nil
					}
				} else {
					return ErrorCode, fmt.Errorf("unknown function: `%v`", inst.Src)
				}
				// local
			case 1:
				ctx := RawContext{Regs: vm.regs}
				res, err := vm.RunInstructions(&ctx, insts[int64(pc)+inst.Constant:])
				if err != nil {
					return res, err
				}
				vm.regs[asm.R0] = uint64(res)
			case 2:
				// runtime
				return ErrorCode, fmt.Errorf("not supported function call: `%v`", inst.Src)
			}

		//
		case asm.Exit.Op(asm.ImmSource):
			return int64(vm.regs[asm.R0]), nil
		default:
			if opcode.Class().IsALU() && opcode.ALUOp() == asm.Swap {
				buff := make([]byte, 8)
				var bo binary.ByteOrder
				switch opcode.Endianness() {
				case asm.LE:
					bo = binary.LittleEndian
				case asm.BE:
					bo = binary.BigEndian
				default:
					return ErrorCode, fmt.Errorf("unknown endianness: %v", inst)
				}

				switch inst.Constant {
				case 16:
					ByteOrder.PutUint16(buff[:2], uint16(vm.regs[inst.Dst]))
					vm.regs[inst.Dst] = uint64(bo.Uint16(buff[:2]))
				case 32:
					ByteOrder.PutUint32(buff[:4], uint32(vm.regs[inst.Dst]))
					vm.regs[inst.Dst] = uint64(bo.Uint32(buff[:4]))
				case 64:
					ByteOrder.PutUint64(buff[:8], uint64(vm.regs[inst.Dst]))
					vm.regs[inst.Dst] = uint64(bo.Uint64(buff[:8]))
				}
			} else {
				return ErrorCode, fmt.Errorf("unknown op: %v", inst)
			}
		}
	}

	return ErrorCode, errors.New("unexpected error")
}

func (vm *VM) LoadMap(name string) (*Map, error) {
	if err := vm.maps.LoadMap(vm.Spec, name); err != nil {
		return nil, err
	}
	return vm.maps.mapByName[name], nil
}

func (vm *VM) LoadMaps(names ...string) error {
	for _, name := range names {
		if _, err := vm.LoadMap(name); err != nil {
			return err
		}
	}
	return nil
}

func (vm *VM) LoadMapsUsedBy(section ...string) error {
	return vm.maps.LoadMaps(vm.Spec, section...)
}

func (vm *VM) loadSection(section string) (*ebpf.ProgramSpec, error) {
	var spec *ebpf.ProgramSpec
	for _, s := range vm.Spec.Programs {
		if progMatch(s, section) {
			spec = s
			break
		}
	}

	if spec == nil {
		return nil, fmt.Errorf("program not found: %s", section)
	}

	if err := vm.maps.LoadMaps(vm.Spec, section); err != nil {
		return nil, err
	}

	program := &ebpf.ProgramSpec{
		Type:         spec.Type,
		Instructions: spec.Instructions,
	}

	return program, nil
}

func (vm *VM) Program(name string) (*ebpf.ProgramSpec, uint32) {
	for i, programSpec := range vm.programs {
		if programSpec.Name == name {
			return programSpec, uint32(i)
		}
	}
	return nil, 0
}

func (vm *VM) AddProgram(program *ebpf.ProgramSpec) uint32 {
	// FD is the index in the map of programs + 1
	fd := uint32(len(vm.programs)) + 1
	vm.programs = append(vm.programs, program)

	return fd
}

func (vm *VM) LoadProgram(section string) (uint32, error) {
	program, err := vm.loadSection(section)
	if err != nil {
		return 0, err
	}

	fd := vm.AddProgram(program)
	return fd, nil
}

func (vm *VM) RunProgram(ctx Context, section string, programType ...ebpf.ProgramType) (int64, error) {
	program, err := vm.loadSection(section)
	if err != nil {
		return ErrorCode, err
	}

	// keep current type and context
	if len(programType) > 0 {
		vm.progType = programType[0]
	} else {
		vm.progType = program.Type
	}
	vm.ctx = ctx

	return vm.RunInstructions(ctx, program.Instructions)
}

func zeroExtend(in int32) uint64 {
	return uint64(uint32(in))
}

func JumpOpCode(class asm.Class, jumpOp asm.JumpOp, source asm.Source) asm.OpCode {
	return asm.OpCode(class).SetJumpOp(jumpOp).SetSource(source)
}
