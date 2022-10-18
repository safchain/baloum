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
	"os"

	"github.com/cilium/ebpf"
	"github.com/safchain/usebpf/pkg/usebpf"
	"go.uber.org/zap"
)

/*func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../ebpf/bin/ex1.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		suggar.Fatalf("opening kprobe: %s", err)
	}

	kp, err := link.Kprobe("do_sys_open", collection.Programs["kprobe_do_sys_open"], nil)
	if err != nil {
		suggar.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	kp, err = link.Kprobe("vfs_open", collection.Programs["kprobe_vfs_open"], nil)
	if err != nil {
		suggar.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	kp, err = link.Kretprobe("do_sys_open", collection.Programs["kretprobe_do_sys_open"], nil)
	if err != nil {
		suggar.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	ch := make(chan bool)
	<-ch
}*/

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../ebpf/bin/ex1.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	tgid := uint64(33)

	fncs := usebpf.Fncs{
		GetCurrentPidTgid: func() (uint64, error) {
			return tgid, nil
		},
		TracePrintk: func(format string, args ...interface{}) {
			suggar.Debugf(format, args...)
		},
	}

	vm := usebpf.NewVM(spec, usebpf.Opts{Fncs: fncs, Logger: suggar})

	var ctx usebpf.Context

	code, err := vm.RunProgram(ctx, "test/ex1")
	if err != nil || code != 0 {
		suggar.Fatalf("unexpected error: %v, %d", err, code)
	}

	data, err := vm.Map("inodes").Lookup(uint64(12345))
	if err != nil {
		suggar.Fatalf("unexpected error: %v, %d", err, code)
	}

	fmt.Printf("Result: %s\n", string(data))
}
