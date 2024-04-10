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
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestBuilderStack(t *testing.T) {
	t.Run("success1", func(t *testing.T) {
		var editor ProgramBuilder

		addr, err := editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("full-one-block", func(t *testing.T) {
		var editor ProgramBuilder

		addr, err := editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)

		_, err = editor.StackAlloc(1)
		assert.NotNil(t, err)
	})

	t.Run("one-block-reuse", func(t *testing.T) {
		var editor ProgramBuilder

		addr, err := editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)

		editor.StackFree(addr)

		addr, err = editor.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("two-blocks", func(t *testing.T) {
		var editor ProgramBuilder

		addr, err := editor.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-256), addr)

		addr, err = editor.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("three-blocks-with-free", func(t *testing.T) {
		var editor ProgramBuilder

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

func TestBuilderInsts(t *testing.T) {
	run := func(prog *Program, pre func(vm *VM), post func(vm *VM, output string)) {
		t.Helper()

		err := prog.Prepare(4096)
		if err != nil {
			t.Fatal(err)
		}

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
			Maps: map[string]*ebpf.MapSpec{
				"map1": {
					Name:       "map1",
					Type:       ebpf.Array,
					KeySize:    4,
					ValueSize:  4,
					MaxEntries: 10,
				},
			},
		}

		vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})
		err = vm.LoadMap("map1")
		assert.Nil(t, err)

		if pre != nil {
			pre(vm)
		}

		var ctx StdContext
		code, err := vm.RunProgram(&ctx, "test/printk")
		assert.Zero(t, code)
		assert.Nil(t, err)

		post(vm, printed)
	}

	t.Run("printk", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(55))
		var2, _ := editor.NewVar(uint32(88))
		var3, _ := editor.NewVar("test")
		editor.Printk("this is a printk test, values: %d %d %s", var1, var2, var3)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "this is a printk test, values: 55 88 test", output)
		})
	})

	t.Run("if-then-else-ok", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.True(),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("if-then-else-ko", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.False(),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("if-then-else-empty-then-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.True(),
			func() error {
				return nil
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "", output)
		})
	})

	t.Run("if-then-else-empty-then-2", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.False(),
			func() error {
				return nil
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("if-then-else-empty", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.True(),
			func() error {
				return nil
			},
			func() error {
				return nil
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
		})
	})

	t.Run("if-then-else-no-else", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.True(),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return nil
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("if-then-else-nested-ok", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.True(),
			func() error {
				return editor.IfThenElse(
					editor.True(),
					func() error {
						return editor.Printk("ok")
					},
					nil,
				)
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("if-then-else-nested-ko", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.True(),
			func() error {
				return editor.IfThenElse(
					editor.False(),
					func() error {
						return editor.Printk("ok")
					},
					func() error {
						return editor.Printk("ko")
					},
				)
			},
			func() error {
				return editor.Printk("no-called")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("strcmp-static-ok", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar("test123")

		editor.IfThenElse(
			editor.StrStaticCmp(var1, "test123"),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("strcmp-static-ko", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar("test123")

		editor.IfThenElse(
			editor.StrStaticCmp(var1, "test567"),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("strcmp-ok", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar("test123")
		var2, _ := editor.NewVar("test123")

		editor.IfThenElse(
			editor.StrCmp(var1, var2, 30),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("strcmp-ko", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar("test123")
		var2, _ := editor.NewVar("test567")

		editor.IfThenElse(
			editor.StrCmp(var1, var2, 30),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("equal-ok-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))
		var2, _ := editor.NewVar(uint32(44))

		editor.IfThenElse(
			editor.Equal(var1, var2),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("equal-ok-2", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))

		editor.IfThenElse(
			editor.Equal(var1, uint32(44)),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("equal-ko-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))
		var2, _ := editor.NewVar(uint32(66))

		editor.IfThenElse(
			editor.Equal(var1, var2),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("equal-ko-2", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))

		editor.IfThenElse(
			editor.Equal(var1, uint32(66)),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("map-lookup", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		key, _ := editor.NewVar(uint32(1))
		valuePtr, _ := editor.NewPtrVar(UInt32PtrType)

		editor.MapLookup("map1", key, valuePtr)

		value, _ := valuePtr.Deref()
		editor.Printk("value: %d", value)

		editor.Return(0)

		editor.Commit()

		run(&prog, func(vm *VM) {
			updated, err := vm.Map("map1").Update(uint32(1), uint32(44), BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "value: 44", output)
		})
	})

	t.Run("map-update", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		key, _ := editor.NewVar(uint32(2))
		value, _ := editor.NewVar(uint32(66))
		ret, _ := editor.NewVar(int32(-1))

		editor.MapUpdate("map1", key, value, ret, BPF_ANY)
		editor.IfThenElse(editor.NotEqual(ret, uint32(0)),
			func() error {
				editor.Return(0)
				return nil
			}, nil)

		valuePtr, _ := editor.NewPtrVar(UInt32PtrType)
		editor.MapLookup("map1", key, valuePtr)

		value, _ = valuePtr.Deref()
		editor.Printk("value: %d", value)

		editor.Return(0)

		editor.Commit()

		run(&prog, func(vm *VM) {
		}, func(_ *VM, output string) {
			assert.Equal(t, "value: 66", output)
		})
	})

	t.Run("and-ok-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.And(editor.True(), editor.True()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("and-ko-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.And(editor.True(), editor.False()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-ko-2", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.And(editor.True(), editor.True(), editor.False()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-ko-3", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.And(editor.False(), editor.True(), editor.False()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-equal-ok-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))
		var2, _ := editor.NewVar(uint32(66))

		editor.IfThenElse(
			editor.And(editor.Equal(var1, uint32(44)), editor.Equal(var2, uint32(66))),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("and-equal-ko-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))
		var2, _ := editor.NewVar(uint32(66))

		editor.IfThenElse(
			editor.And(editor.Equal(var1, uint32(44)), editor.Equal(var2, uint32(77))),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("or-ok-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.Or(editor.False(), editor.True()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("or-ok-2", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.Or(editor.True(), editor.False()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("or-ko-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		editor.IfThenElse(
			editor.Or(editor.False(), editor.False()),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-equal-ok-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))
		var2, _ := editor.NewVar(uint32(66))

		editor.IfThenElse(
			editor.Or(editor.Equal(var1, uint32(44)), editor.Equal(var2, uint32(77))),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("and-equal-ko-1", func(t *testing.T) {
		var prog Program
		editor := prog.Edit(ProgramBuilderOpts{})

		var1, _ := editor.NewVar(uint32(44))
		var2, _ := editor.NewVar(uint32(66))

		editor.IfThenElse(
			editor.Or(editor.Equal(var1, uint32(88)), editor.Equal(var2, uint32(77))),
			func() error {
				return editor.Printk("ok")
			},
			func() error {
				return editor.Printk("ko")
			},
		)
		editor.Return(0)

		editor.Commit()

		run(&prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})
}
