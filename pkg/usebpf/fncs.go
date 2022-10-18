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
	"errors"
	"regexp"
	"strings"

	"github.com/cilium/ebpf/asm"
)

const (
	// static void *(*usebpf_malloc)(__u32 size) = (void *) 0xffff;
	FnMalloc = asm.BuiltinFunc(0xffff)

	// static int (*usebpf_call)(struct usebpf_ctx *ctx, const char *section) = (void *) 0xfffe;
	FnCall = asm.BuiltinFunc(0xfffe)

	// static int (*usebpf_strcmp)(const char *str1, const char *str2) = (void *)0xfffd;
	FnStrCmp = asm.BuiltinFunc(0xfffd)

	// TODO add assert for testing. It will check with a message and return an vm exception
)

func FnMallocImpl(vm *VM, inst *asm.Instruction) error {
	vm.regs[asm.R0] = vm.heap.AllocWith(make([]byte, vm.regs[asm.R1]))
	return nil
}

func FnCallImpl(vm *VM, inst *asm.Instruction) error {
	data, err := vm.getBytes(vm.regs[asm.R1], 0)
	if err != nil {
		return err
	}
	var ctx Context
	if err := ctx.Parse(data); err != nil {
		return err
	}

	section, err := vm.getString(vm.regs[asm.R2])
	if err != nil {
		return err
	}

	vm.Opts.Logger.Debugf("> UseBPF call %s", section)

	code, err := vm.RunProgram(ctx, section)
	if err != nil {
		return err
	}
	vm.regs[asm.R0] = uint64(code)

	return nil
}

func FnStrCmpImpl(vm *VM, inst *asm.Instruction) error {
	code := ErrorCode
	vm.regs[asm.R0] = uint64(code)

	str1, err := vm.getString(vm.regs[asm.R1])
	if err != nil {
		return err
	}

	str2, err := vm.getString(vm.regs[asm.R2])
	if err != nil {
		return err
	}

	ret := strings.Compare(str1, str2)
	vm.regs[asm.R0] = uint64(ret)

	return nil
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
			vm.Opts.Fncs.TracePrintk(format)
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
		vm.Opts.Fncs.TracePrintk(format, values...)
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
		value, err := vm.Opts.Fncs.GetCurrentPidTgid()
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
		value, err := vm.Opts.Fncs.KtimeGetNS()
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
