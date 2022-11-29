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

func TestCall(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_call.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	tgid := uint64(33)

	fncs := Fncs{
		GetCurrentPidTgid: func(vm *VM) (uint64, error) {
			return tgid, nil
		},
	}

	t.Run("simple-call", func(t *testing.T) {
		vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})

		var ctx Context
		code, err := vm.RunProgram(ctx, "test/simple_call")
		assert.Zero(t, code)
		assert.Nil(t, err)

		data, err := vm.Map("cache").Lookup(tgid)
		assert.Nil(t, err)
		assert.NotNil(t, data)
		assert.Equal(t, uint64(12345), ByteOrder.Uint64(data))

		code, err = vm.RunProgram(ctx, "kretprobe/vfs_open")
		assert.Zero(t, code)
		assert.Nil(t, err)

		data, err = vm.Map("cache").Lookup(tgid)
		assert.Nil(t, err)
		assert.Nil(t, data)
	})

	t.Run("nested-call", func(t *testing.T) {
		vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})

		var ctx Context
		code, err := vm.RunProgram(ctx, "test/nested_call")
		assert.Zero(t, code)
		assert.Nil(t, err)

		data, err := vm.Map("cache").Lookup(tgid)
		assert.Nil(t, err)
		assert.Nil(t, data)
	})
}

func TestKTime(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_ktime.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	ns := uint64(44)

	fncs := Fncs{
		KtimeGetNS: func(vm *VM) (uint64, error) {
			return ns, nil
		},
	}

	vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})

	var ctx Context
	code, err := vm.RunProgram(ctx, "test/ktime")
	assert.Zero(t, code)
	assert.Nil(t, err)
}

func TestPrintk(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_printk.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	var printed string

	fncs := Fncs{
		TracePrintk: func(vm *VM, format string, args ...interface{}) error {
			printed = fmt.Sprintf(format, args...)
			return nil
		},
	}

	vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})

	var ctx Context
	code, err := vm.RunProgram(ctx, "test/printk")
	assert.Zero(t, code)
	assert.Nil(t, err)
	assert.Equal(t, "this is a printk test, values: 123:hello", printed)
}

func TestSyncAdd(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_sync_add.o")
	if err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Fatal(err)
	}

	vm := NewVM(spec, Opts{Logger: suggar})

	var ctx Context
	code, err := vm.RunProgram(ctx, "test/sync_add")
	assert.Zero(t, code)
	assert.Nil(t, err)

	data, err := vm.Map("cache").Lookup(uint64(4))
	assert.Nil(t, err)
	assert.Equal(t, uint64(14), ByteOrder.Uint64(data))
}
