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
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestStackAlloc(t *testing.T) {
	t.Run("success1", func(t *testing.T) {
		var editor ProgramEditor

		addr, err := editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("full-one-block", func(t *testing.T) {
		var editor ProgramEditor

		addr, err := editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)

		_, err = editor.StackAlloc(1)
		assert.NotNil(t, err)
	})

	t.Run("one-block-reuse", func(t *testing.T) {
		var editor ProgramEditor

		addr, err := editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)

		editor.StackFree(addr)

		addr, err = editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("two-blocks", func(t *testing.T) {
		var editor ProgramEditor

		addr, err := editor.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-256), addr)

		addr, err = editor.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("three-blocks-with-free", func(t *testing.T) {
		var editor ProgramEditor

		addr1, err := editor.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-256), addr1)

		addr2, err := editor.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr2)

		editor.StackFree(addr1)

		addr3, err := editor.StackAlloc(128)
		assert.Nil(t, err)
		assert.Equal(t, int16(-128), addr3)

		addr4, err := editor.StackAlloc(32)
		assert.Nil(t, err)
		assert.Equal(t, int16(-160), addr4)

		addr5, err := editor.StackAlloc(32)
		assert.Nil(t, err)
		assert.Equal(t, int16(-192), addr5)

		_, err = editor.StackAlloc(65)
		assert.NotNil(t, err)
	})
}

func TestDagVerifier(t *testing.T) {
	t.Run("ko", func(t *testing.T) {
		var prog Program

		prog.Append(
			asm.Ja.Label("jump1"),
			asm.Mov.Imm(asm.R1, 1).WithSymbol("jump2"),
			asm.Mov.Imm(asm.R1, 1).WithSymbol("jump1"),
			asm.Ja.Label("jump2"),
		)

		err := prog.Prepare(4096)
		assert.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		var prog Program

		prog.Append(
			asm.Ja.Label("jump1"),
			asm.Mov.Imm(asm.R1, 1).WithSymbol("jump2"),
			asm.Ja.Label("jump3"),
			asm.Mov.Imm(asm.R1, 1).WithSymbol("jump1"),
			asm.Ja.Label("jump2"),
			asm.Mov.Imm(asm.R1, 1).WithSymbol("jump3"),
		)

		err := prog.Prepare(4096)
		assert.NoError(t, err)
	})
}

func TestEditor(t *testing.T) {

	t.Run("printk", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramEditorOpts{})

		editor.NewVar("var1", uint32(55))
		editor.NewVar("var2", uint32(88))
		editor.NewVar("var3", "test")
		editor.Printk(">> %d %d %s", "var1", "var2", "var3")

		err := editor.Commit()
		assert.NoError(t, err)

		err = prog.Prepare(4096)
		assert.NoError(t, err)

		fmt.Printf("PROG: %+v\n", prog.insts)

		logger, _ := zap.NewDevelopment()
		defer logger.Sync()

		suggar := logger.Sugar()
		var printed string

		fncs := Fncs{
			TracePrintk: func(vm *VM, format string, args ...interface{}) error {
				printed = fmt.Sprintf(format, args...)
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

		vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})

		var ctx StdContext
		code, err := vm.RunProgram(&ctx, "test/printk")
		assert.Zero(t, code)
		assert.Nil(t, err)
		assert.Equal(t, "this is a printk test, values: 123:hello", printed)
	})
}
