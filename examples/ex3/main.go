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
	"flag"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/safchain/baloum/pkg/baloum"
	"go.uber.org/zap"
)

func run(test bool) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	debugger := baloum.NewDebugger(true, nil)
	defer debugger.Close()

	var prog baloum.Program
	editor := prog.Edit(baloum.ProgramBuilderOpts{})

	var1 := editor.NewVarV(uint32(55))
	var2 := editor.NewVarV(uint32(88))
	var3 := editor.NewVarV("test123")
	var4 := editor.NewVarV("test123")

	editor.IfThenElse(
		editor.StrCmp(var3, var4, 30),
		func() {
			editor.Printk(">> %d %d %s", var1, var2, var3)
		}, func() {
			editor.Printk(">>> else")
		})

	editor.Return(0)

	if err := editor.Commit(); err != nil {
		suggar.Panic(err)
	}

	if err := prog.Prepare(4096); err != nil {
		suggar.Panicf("unexpected error: %v", err)
	}

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"kprobe_execve": {
				Name:         "kprobe_execve",
				SectionName:  "kprobe/sys_execve",
				Type:         ebpf.Kprobe,
				Instructions: prog.Instructions(),
				License:      "GPL",
			},
		},
	}

	if !test {
		collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
		if err != nil {
			suggar.Fatalf("opening kprobe: %s", err)
		}

		kp, err := link.Kprobe("sys_execve", collection.Programs["kprobe_execve"], nil)
		if err != nil {
			suggar.Fatalf("opening kprobe: %s", err)
		}
		defer kp.Close()

		ch := make(chan bool)

		fmt.Println("Started, ctrl-c to stop")
		<-ch
	} else {
		fncs := baloum.Fncs{
			TracePrintk: func(vm *baloum.VM, format string, args ...interface{}) error {
				suggar.Infof(format, args...)
				return nil
			},
		}

		vm := baloum.NewVM(spec, baloum.Opts{Fncs: fncs, Observer: debugger})

		var ctx baloum.StdContext

		code, err := vm.RunProgram(&ctx, "kprobe/sys_execve")
		if err != nil || code != 0 {
			suggar.Panicf("unexpected error: %v, %d", err, code)
		}

		fmt.Printf("Done\n")
	}
}

func main() {
	var test = flag.Bool("test", false, "run test program")
	flag.Parse()

	run(*test)
}
