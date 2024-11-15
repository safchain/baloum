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
	"regexp"
	"strings"
	"time"

	"github.com/cilium/ebpf/asm"
)

const (
	// static void *(*baloum_malloc)(__u32 size) = (void *) 0xffff;
	FnMalloc = asm.BuiltinFunc(0xffff)

	// static int (*baloum_call)(struct baloum_ctx *ctx, const char *section) = (void *) 0xfffe;
	FnCall = asm.BuiltinFunc(0xfffe)

	// static int (*baloum_strcmp)(const char *s1, const char *s2) = (void *)0xfffd;
	FnStrCmp = asm.BuiltinFunc(0xfffd)

	// static int (*baloum_memcmp)(const void *b1, const void *b2, __u32 size) = (void *)0xfffc;
	FnMemCmp = asm.BuiltinFunc(0xfffc)

	// static int (*baloum_sleep)(__u64 ns) = (void *)0xfffb;
	FnSleep = asm.BuiltinFunc(0xfffb)

	// static int (*baloum_memcpy)(const void *b1, const void *b2, __u32 size) = (void *)0xfffa;
	FnMemCpy = asm.BuiltinFunc(0xfffa)
)

var (
	builtInFunc = map[asm.BuiltinFunc]func(*VM, *asm.Instruction) error{
		// extensions
		FnMalloc: FnMallocImpl,
		FnCall:   FnCallImpl,
		FnStrCmp: FnStrCmpImpl,
		FnMemCmp: FnMemCmpImpl,
		FnSleep:  FnSleepImpl,
		FnMemCpy: FnMemCpyImpl,

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
		asm.FnGetSmpProcessorId: FnGetSmpProcessorIdImpl,
		asm.FnTailCall:          FnTailCallImpl,
	}
)

func FnSleepImpl(vm *VM, inst *asm.Instruction) error {
	if vm.Opts.Fncs.Sleep != nil {
		vm.Opts.Fncs.Sleep(vm, time.Duration(vm.regs[asm.R1]))
	}
	return nil
}

func FnMallocImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = vm.heap.AllocWith(make([]byte, vm.regs[asm.R1]))
	return nil
}

func FnCallImpl(vm *VM, inst *asm.Instruction) error {
	data, err := vm.getBytes(vm.regs[asm.R1], 0)
	if err != nil {
		return err
	}
	var ctx StdContext
	if err := ctx.Parse(data); err != nil {
		return err
	}

	section, err := vm.getString(vm.regs[asm.R2])
	if err != nil {
		return err
	}

	vm.Opts.Logger.Debugf("> UseBPF call %s", section)

	code, err := vm.RunProgram(&ctx, section)
	if err != nil {
		return err
	}
	vm.regs[asm.R0] = uint64(code)

	return nil
}

func FnStrCmpImpl(vm *VM, inst *asm.Instruction) error {
	code := ErrorCode
	vm.regs[asm.R0] = uint64(code)

	s1, err := vm.getString(vm.regs[asm.R1])
	if err != nil {
		return err
	}

	s2, err := vm.getString(vm.regs[asm.R2])
	if err != nil {
		return err
	}

	ret := strings.Compare(s1, s2)
	vm.regs[asm.R0] = uint64(ret)

	return nil
}

func FnMemCmpImpl(vm *VM, inst *asm.Instruction) error {
	code := ErrorCode
	vm.regs[asm.R0] = uint64(code)

	size := vm.regs[asm.R3]

	b1, err := vm.getBytes(vm.regs[asm.R1], uint64(size))
	if err != nil {
		return err
	}

	b2, err := vm.getBytes(vm.regs[asm.R2], uint64(size))
	if err != nil {
		return err
	}

	ret := bytes.Compare(b1, b2)
	vm.regs[asm.R0] = uint64(ret)

	return nil
}

func FnMemCpyImpl(vm *VM, inst *asm.Instruction) error {
	code := ErrorCode
	vm.regs[asm.R0] = uint64(code)

	size := vm.regs[asm.R3]

	srcBytes, err := vm.getBytes(vm.regs[asm.R2], size)
	if err != nil {
		return err
	}

	return vm.setBytes(vm.regs[asm.R1], srcBytes, size)
}

var (
	reFmt = regexp.MustCompile("(%[^%])")
)

func FnTracePrintkImpl(vm *VM, inst *asm.Instruction) error {
	format, err := vm.getString(vm.regs[asm.R1])
	if err != nil {
		return err
	}

	phs := reFmt.FindAllString(format, -1)
	if len(phs) > 3 {
		return errors.New("number of placeholder exceeded")
	} else if len(phs) == 0 {
		if vm.Opts.Fncs.TracePrintk != nil {
			vm.Opts.Fncs.TracePrintk(vm, format)
		}
		return nil
	}

	values := make([]interface{}, len(phs))

	for i, ph := range phs {
		var reg asm.Register
		switch i {
		case 0:
			reg = asm.R3
		case 1:
			reg = asm.R4
		case 2:
			reg = asm.R5
		}

		var value interface{}
		if ph == "%s" {
			value, err = vm.getString(vm.regs[reg])
			if err != nil {
				return err
			}
		} else {
			value = vm.regs[reg]
		}

		values[i] = value
	}

	if vm.Opts.Fncs.TracePrintk != nil {
		vm.Opts.Fncs.TracePrintk(vm, format, values...)
	}

	return nil
}

func FnProbeReadImpl(vm *VM, inst *asm.Instruction) error {
	size := vm.regs[asm.R2]

	srcBytes, err := vm.getBytes(vm.regs[asm.R3], size)
	if err != nil {
		return err
	}

	dstBytes, err := vm.getBytes(vm.regs[asm.R1], size)
	if err != nil {
		return err
	}

	copy(dstBytes, srcBytes)

	return nil
}

func FnProbeReadStrImpl(vm *VM, inst *asm.Instruction) error {
	size := vm.regs[asm.R2]

	src, err := vm.getString(vm.regs[asm.R3])
	if err != nil {
		return err
	}

	dstBytes, err := vm.getBytes(vm.regs[asm.R1], size)
	if err != nil {
		return err
	}

	srcBytes := []byte(src)
	if len(src) > int(size) {
		copy(dstBytes, srcBytes[:size])
	} else {
		copy(dstBytes, srcBytes)
	}

	return nil
}

func FnGetCurrentPidTgidImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0
	if vm.Opts.Fncs.GetCurrentPidTgid != nil {
		value, err := vm.Opts.Fncs.GetCurrentPidTgid(vm)
		if err != nil {
			return err
		}
		vm.regs[asm.R0] = value
	}
	return nil
}

func FnKtimeGetNsImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0
	if vm.Opts.Fncs.KtimeGetNS != nil {
		value, err := vm.Opts.Fncs.KtimeGetNS(vm)
		if err != nil {
			return err
		}
		vm.regs[asm.R0] = value
	}
	return nil
}

func FnMapLookupElemImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0

	_map := vm.maps.GetMapById(int(vm.regs[asm.R1]))
	if _map == nil {
		return errors.New("map unknown")
	}

	keyAddr := vm.regs[asm.R2]
	key, err := vm.getBytes(keyAddr, uint64(_map.KeySize()))
	if err != nil {
		return err
	}

	if value, err := _map.LookupAddr(key); err == nil {
		vm.regs[asm.R0] = value
	}

	return nil
}

func FnMapUpdateElemImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0

	_map := vm.maps.GetMapById(int(vm.regs[asm.R1]))
	if _map == nil {
		return errors.New("map unknown")
	}

	keyAddr := vm.regs[asm.R2]
	key, err := vm.getBytes(keyAddr, uint64(_map.KeySize()))
	if err != nil {
		return err
	}

	valueAddr := vm.regs[asm.R3]
	value, err := vm.getBytes(valueAddr, uint64(_map.ValueSize()))
	if err != nil {
		return err
	}

	updated, err := _map.Update(key, value, MapUpdateType(vm.regs[asm.R4]))
	if !updated {
		code := int64(ErrorCode)
		vm.regs[asm.R0] = uint64(code)
	}

	return err
}

func FnMapDeleteElemImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0

	_map := vm.maps.GetMapById(int(vm.regs[asm.R1]))
	if _map == nil {
		return errors.New("map unknown")
	}

	keyAddr := vm.regs[asm.R2]
	key, err := vm.getBytes(keyAddr, uint64(_map.KeySize()))
	if err != nil {
		return err
	}

	deleted, err := _map.Delete(key)
	if !deleted {
		code := int64(ErrorCode)
		vm.regs[asm.R0] = uint64(code)
	}

	return err
}

func FnPerfEventOutputImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0

	_map := vm.maps.GetMapById(int(vm.regs[asm.R2]))
	if _map == nil {
		return errors.New("map unknown")
	}

	// skip CPU

	size := vm.regs[asm.R5]

	eventAddr := vm.regs[asm.R4]
	data, err := vm.getBytes(eventAddr, size)
	if err != nil {
		return err
	}

	return _map.Write(data, size)
}

func FnGetSmpProcessorIdImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = 0

	if vm.Opts.Fncs.GetSmpProcessorId != nil {
		id, err := vm.Opts.Fncs.GetSmpProcessorId(vm)
		if err != nil {
			return err
		}
		vm.regs[asm.R0] = id
	}

	return nil
}

func FnTailCallImpl(vm *VM, inst *asm.Instruction) error {
	if vm.tailCails >= 32 {
		return errors.New("maximum tail calls reach")
	}
	vm.tailCails++

	_map := vm.maps.GetMapById(int(vm.regs[asm.R2]))
	if _map == nil {
		return errors.New("map unknown")
	}

	var bytes []byte
	var err error

	switch _map.keySize {
	case 4:
		bytes, err = _map.Lookup(uint32(vm.regs[asm.R3]))
	case 8:
		bytes, err = _map.Lookup(uint64(vm.regs[asm.R3]))
	default:
		return errors.New("key size not supported")
	}

	if err != nil {
		return nil // lookup failed, continue without running the prog
	}

	var fd int
	switch _map.valueSize {
	case 4:
		fd = int(ByteOrder.Uint32(bytes))
	case 8:
		fd = int(ByteOrder.Uint64(bytes))
	default:
		return errors.New("value size not supported")
	}

	if fd == 0 {
		return errors.New("program not found")
	}

	progIndex := fd - 1

	if progIndex > len(vm.programs) {
		return errors.New("out of bound")
	}

	program := vm.programs[progIndex]
	if program.Type != vm.progType {
		return errors.New("program types differ")
	}

	vm.regs[asm.R0] = 0

	ret, err := vm.RunInstructions(vm.ctx, program.Instructions)
	vm.regs[asm.R0] = uint64(ret)

	return err
}
