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
	"github.com/safchain/baloum/pkg/baloum"
	"go.uber.org/zap"
)

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("./ebpf/bin/ex2.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	fncs := baloum.Fncs{
		TracePrintk: func(vm *baloum.VM, format string, args ...interface{}) error {
			suggar.Debugf(format, args...)
			return nil
		},
	}

	debugger := baloum.NewDebugger(true, nil)
	defer debugger.Close()

	vm := baloum.NewVM(spec, baloum.Opts{Fncs: fncs, Observer: debugger})

	var ctx baloum.StdContext

	code, err := vm.RunProgram(&ctx, "test/ex2")
	if err != nil || code != 0 {
		suggar.Fatalf("unexpected error: %v, %d", err, code)
	}

	fmt.Printf("Done\n")
}
