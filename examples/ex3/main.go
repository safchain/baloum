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

package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/safchain/baloum/pkg/baloum"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	debugger := baloum.NewDebugger(true, nil)
	defer debugger.Close()

	var prog baloum.Program
	editor := prog.Edit(baloum.ProgramEditorOpts{})

	editor.NewVar("var1", uint32(55))
	editor.NewVar("var2", uint32(88))
	editor.NewVar("var3", "test123")
	editor.Printk(">> %d %d %s", "var1", "var2", "var3")
	editor.Return(0)

	if err := editor.Commit(); err != nil {
		suggar.Panicf("unexpected error: %v", err)
	}

	if err := prog.Prepare(4096); err != nil {
		suggar.Panicf("unexpected error: %v", err)
	}

	fncs := baloum.Fncs{
		TracePrintk: func(vm *baloum.VM, format string, args ...interface{}) error {
			suggar.Infof(format, args...)
			return nil
		},
	}

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"test/printk": {
				Name:         "test/printk",
				SectionName:  "test/printk",
				Type:         ebpf.Kprobe,
				Instructions: prog.Instructions(),
			},
		},
	}

	vm := baloum.NewVM(spec, baloum.Opts{Fncs: fncs, Observer: debugger})

	var ctx baloum.StdContext

	code, err := vm.RunProgram(&ctx, "test/printk")
	if err != nil || code != 0 {
		suggar.Panicf("unexpected error: %v, %d", err, code)
	}

	fmt.Printf("Done\n")
}
