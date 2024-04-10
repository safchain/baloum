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

	key, _ := editor.NewVar(uint32(1))
	value, _ := editor.NewVar(uint32(77))
	ret, _ := editor.NewVar(uint32(0))

	editor.MapUpdate("map2", key, value, ret, baloum.BPF_ANY)

	valuePtr, _ := editor.NewPtrVar(baloum.UInt32PtrType)

	editor.MapLookup("map2", key, valuePtr)
	editor.IfThenElse(editor.IsNotNull(valuePtr), func() error {
		value, _ = valuePtr.Deref()
		return editor.Printk("value: %d", value)
	}, nil)

	editor.Return(0)

	editor.Commit()

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
		Maps: map[string]*ebpf.MapSpec{
			"map1": {
				Name:       "map1",
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 10,
			},
			"map2": {
				Name:       "map2",
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 10,
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
		vm.LoadMap("map1")
		vm.LoadMap("map2")

		vm.Map("map2").Update(uint32(1), uint32(44), baloum.BPF_ANY)

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
