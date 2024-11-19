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
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestTailCall(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_prog_array.o")
	if err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Fatal(err)
	}

	fncs := Fncs{
		TracePrintk: func(vm *VM, format string, args ...interface{}) error {
			fmt.Printf(format, args...)
			return nil
		},
	}

	vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})
	err = vm.LoadMapsUsedBy("test/tail_call")
	if err != nil {
		log.Fatal(err)
	}

	_, err = vm.Map("data").Update(uint64(0), uint64(20), BPF_ANY)
	if err != nil {
		log.Fatal(err)
	}

	fd, err := vm.LoadProgram("test/tail_call_prog")
	if err != nil {
		log.Fatal(err)
	}

	if _, err = vm.Map("tail_calls").Update(uint32(0), fd, BPF_ANY); err != nil {
		log.Fatal(err)
	}

	var ctx StdContext
	code, err := vm.RunProgram(&ctx, "test/tail_call")
	assert.Equal(t, int64(72), code)
	assert.Nil(t, err)

	data, err := vm.Map("data").Lookup(uint64(0))
	assert.Nil(t, err)
	assert.Equal(t, uint64(30), ByteOrder.Uint64(data))
}
