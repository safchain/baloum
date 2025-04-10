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
	"github.com/safchain/baloum/pkg/baloum/debugger"
	"go.uber.org/zap"
)

func run(test bool) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	debugger := debugger.NewDebugger(true, nil)
	defer debugger.Close()

	var prog baloum.Program
	pb := prog.Edit(baloum.ProgramBuilderOpts{})

	key := pb.NewVarV(uint32(1))
	value := pb.NewVarV(uint64(77))
	ret := pb.NewVarV(uint32(0))

	pb.MapUpdate("map1", key, value, ret, baloum.BPF_ANY)

	valuePtr := pb.NewPtrVar()

	pb.MapLookup("map1", key, valuePtr)
	pb.IfThenElse(pb.IsNotNull(valuePtr), func() {
		pb.Printk("value: %d", valuePtr.Deref(baloum.UInt64Type, 0))
	}, nil)

	pb.Return(0)

	pb.Commit()

	if err := prog.Prepare(4096); err != nil {
		suggar.Panicf("unexpected error: %v", err)
	}

	prog.PrintInstructions()

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
				ValueSize:  8,
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

		vm.Map("map1").Update(uint32(1), uint32(44), baloum.BPF_ANY)

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
