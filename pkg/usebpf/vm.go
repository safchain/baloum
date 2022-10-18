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

package usebpf

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

var (
	builtInFunc = map[asm.BuiltinFunc]func(*VM, *asm.Instruction) error{
		// extensions
		FnMalloc: FnMallocImpl,
		FnCall:   FnCallImpl,
		FnStrCmp: FnStrCmpImpl,

		// bpf helpers
		asm.FnTracePrintk:       FnTracePrintkImpl,
		asm.FnGetCurrentPidTgid: FnGetCurrentPidTgidImpl,
		asm.FnKtimeGetNs:        FnKtimeGetNsImpl,
		asm.FnMapLookupElem:     FnMapLookupElemImpl,
		asm.FnMapUpdateElem:     FnMapUpdateElemImpl,
		asm.FnMapDeleteElem:     FnMapDeleteElemImpl,
		asm.FnPerfEventOutput:   FnPerfEventOutputImpl,
		asm.FnProbeRead:         FnProbeReadImpl,
		asm.FnProbeReadStr:      FnProbeReadStrImpl,
	}
)

type vmState struct {
	regs  Regs
	stack []byte
	pc    int
}

type VM struct {
	Spec  *ebpf.CollectionSpec
	Opts  Opts
	stack []byte
	heap  *Heap
	regs  Regs
	pc    int
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
		maps:  NewMapCollection(),
	}
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
		pc:    vm.pc,
	}
}

func (vm *VM) loadState(state *vmState) {
	vm.stack = state.stack
	vm.regs = state.regs
	vm.pc = state.pc
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
	vm.pc = 0
	vm.stack = make([]byte, vm.Opts.StackSize)
	vm.regs[asm.RFP] = uint64(len(vm.stack))
	vm.regs[asm.R1] = vm.heap.AllocWith(ctx.Bytes())

	if err := vm.maps.LoadMaps(vm.heap, vm.Spec, section); err != nil {
		return ErrorCode, err
	}

	for pc, inst := range prog.Instructions {
		vm.Opts.Logger.Debugf("%d > %v", pc, inst)

		if pc != vm.pc {
			continue
		}
		vm.pc++

		switch inst.OpCode {
		//
		case asm.LoadMemOp(asm.DWord):
			srcAddr := vm.regs[inst.Src] + uint64(inst.Offset)
			value, err := vm.getUint64(srcAddr)
			if err != nil {
				return ErrorCode, err
			}
			vm.regs[inst.Dst] = value

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
		case asm.RSh.Op(asm.ImmSource):
			vm.regs[inst.Dst] >>= uint64(inst.Constant)

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
		case asm.Mov.Op(asm.RegSource):
			vm.regs[inst.Dst] = vm.regs[inst.Src]
		case asm.Mov.Op(asm.ImmSource):
			vm.regs[inst.Dst] = uint64(inst.Constant)

		//
		case asm.Add.Op(asm.ImmSource):
			vm.regs[inst.Dst] += uint64(inst.Constant)

		//
		case asm.JEq.Op(asm.ImmSource):
			if vm.regs[inst.Dst] == uint64(inst.Constant) {
				vm.pc = pc + int(inst.Offset)
			}
		case asm.Ja.Op(asm.ImmSource):
			pc = vm.pc + int(inst.Offset)
		case asm.JNE.Op(asm.ImmSource):
			if vm.regs[inst.Dst] != uint64(inst.Constant) {
				vm.pc = pc + int(inst.Offset)
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
