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

import "github.com/cilium/ebpf/asm"

const (
	DEFAULT_STACK_SIZE = 512
)

type Fncs struct {
	GetCurrentPidTgid func() (uint64, error)
	KtimeGetNS        func() (uint64, error)
	TracePrintk       func(format string, args ...interface{})
}

type Opts struct {
	StackSize int
	Fncs      Fncs
	RawFncs   map[asm.BuiltinFunc]func(*VM, *asm.Instruction) error
	Logger    Logger
}

func (o *Opts) applyDefault() {
	if o.StackSize == 0 {
		o.StackSize = DEFAULT_STACK_SIZE
	}

	if o.Logger == nil {
		o.Logger = &NullLogger{}
	}
}
