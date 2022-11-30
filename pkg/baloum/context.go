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

	"github.com/cilium/ebpf/asm"
)

const (
	CTX_SIZE = 5 * 8 // 5 argument
)

type Context interface {
	SetRegs(vm *VM)
}

/*
struct baloum_ctx {
	u64 arg0;
	u64 arg1;
	u64 arg2;
	u64 arg3;
	u64 arg4;
};
*/
type StdContext struct {
	Arg0 uint64
	Arg1 uint64
	Arg2 uint64
	Arg3 uint64
	Arg4 uint64
}

func (ctx *StdContext) Parse(data []byte) error {
	if len(data) < CTX_SIZE {
		return errors.New("not enough data")
	}

	var offset int
	ctx.Arg0 = ByteOrder.Uint64(data[offset : offset+8])
	offset += 8
	ctx.Arg1 = ByteOrder.Uint64(data[offset : offset+8])
	offset += 8
	ctx.Arg2 = ByteOrder.Uint64(data[offset : offset+8])
	offset += 8
	ctx.Arg3 = ByteOrder.Uint64(data[offset : offset+8])
	offset += 8
	ctx.Arg4 = ByteOrder.Uint64(data[offset : offset+8])

	return nil
}

func (ctx *StdContext) SetRegs(vm *VM) {
	vm.regs[asm.R1] = vm.heap.AllocWith(ctx.Bytes())
}

type RawContext struct {
	Regs Regs
}

func (ctx *RawContext) SetRegs(vm *VM) {
	vm.regs = ctx.Regs
}
