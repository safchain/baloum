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
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestBuilderStack(t *testing.T) {
	t.Run("success1", func(t *testing.T) {
		builder := NewProgramBuilder(nil, ProgramBuilderOpts{})

		addr := builder.stackAlloc(512)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("full-one-block", func(t *testing.T) {
		builder := NewProgramBuilder(nil, ProgramBuilderOpts{})

		addr := builder.stackAlloc(512)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-512), addr)

		builder.stackAlloc(1)
		assert.NotNil(t, builder.Error())
	})

	t.Run("one-block-reuse", func(t *testing.T) {
		builder := NewProgramBuilder(nil, ProgramBuilderOpts{})

		addr := builder.stackAlloc(512)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-512), addr)

		builder.stackFree(addr)

		addr = builder.stackAlloc(512)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("two-blocks", func(t *testing.T) {
		builder := NewProgramBuilder(nil, ProgramBuilderOpts{})

		addr := builder.stackAlloc(256)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-256), addr)

		addr = builder.stackAlloc(256)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("three-blocks-with-free", func(t *testing.T) {
		builder := NewProgramBuilder(nil, ProgramBuilderOpts{})

		addr1 := builder.stackAlloc(256)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-256), addr1)

		addr2 := builder.stackAlloc(256)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-512), addr2)

		builder.stackFree(addr1)

		addr3 := builder.stackAlloc(128)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-128), addr3)

		addr4 := builder.stackAlloc(32)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-160), addr4)

		addr5 := builder.stackAlloc(32)
		assert.Nil(t, builder.Error())
		assert.Equal(t, int16(-192), addr5)

		builder.stackAlloc(65)
		assert.NotNil(t, builder.Error())
	})
}

func TestBuilderRegAlloc(t *testing.T) {
	builder := NewProgramBuilder(nil, ProgramBuilderOpts{})

	assert.Equal(t, 4, len(builder.regAlloc.available))

	v1 := builder.NewNumberVar(Int32Type, 1)
	assert.Equal(t, 3, len(builder.regAlloc.available))
	assert.NotEqual(t, RNULL, v1.reg)
	assert.Equal(t, int16(math.MaxInt16), v1.addr)

	v2 := builder.NewNumberVar(Int32Type, 1)
	assert.Equal(t, 2, len(builder.regAlloc.available))
	assert.NotEqual(t, RNULL, v2.reg)
	assert.Equal(t, int16(math.MaxInt16), v2.addr)
	assert.NotEqual(t, RNULL, v1.reg)
	assert.Equal(t, int16(math.MaxInt16), v1.addr)

	v3 := builder.NewNumberVar(Int32Type, 1)
	assert.Equal(t, 1, len(builder.regAlloc.available))
	assert.NotEqual(t, RNULL, v3.reg)
	assert.Equal(t, int16(math.MaxInt16), v3.addr)
	assert.NotEqual(t, RNULL, v1.reg)
	assert.Equal(t, int16(math.MaxInt16), v1.addr)

	v4 := builder.NewNumberVar(Int32Type, 1)
	assert.Equal(t, 0, len(builder.regAlloc.available))
	assert.NotEqual(t, RNULL, v4.reg)
	assert.Equal(t, int16(math.MaxInt16), v4.addr)
	assert.NotEqual(t, RNULL, v1.reg)
	assert.Equal(t, int16(math.MaxInt16), v1.addr)

	v5 := builder.NewNumberVar(Int32Type, 1)
	assert.Equal(t, 0, len(builder.regAlloc.available))
	assert.NotEqual(t, RNULL, v5.reg)
	assert.Equal(t, int16(math.MaxInt16), v5.addr)
	assert.Equal(t, RNULL, v1.reg)
	assert.NotEqual(t, int16(math.MaxInt16), v1.addr)
}

func TestDeadCodeElimination(t *testing.T) {
	t.Run("test-1", func(t *testing.T) {
		var insts asm.Instructions

		insts = append(insts,
			asm.Return(),
			asm.Mov.Imm(asm.R1, 1),
		)
		assert.Equal(t, 2, len(insts))

		cleaned := deadCodeElimination(insts)
		assert.Equal(t, 1, len(cleaned))
	})

	t.Run("test-2", func(t *testing.T) {
		var insts asm.Instructions

		insts = append(insts,
			asm.Ja.Label("jmp1"),
			asm.Return(),
			asm.Mov.Imm(asm.R1, 1).WithSymbol("jmp1"),
		)
		assert.Equal(t, 3, len(insts))

		cleaned := deadCodeElimination(insts)
		assert.Equal(t, 3, len(cleaned))
	})
}

type Dentry struct {
	MountID uint64
	Inode   uint32
	_       uint32
}

// TODO: generate unmarshaller + marshaller based on tag
func (d *Dentry) MarshalBinary() ([]byte, error) {
	sizeOfMountID := unsafe.Sizeof(d.MountID)
	data := make([]byte, d.Sizeof())

	binary.NativeEndian.PutUint64(data, d.MountID)
	binary.NativeEndian.PutUint32(data[sizeOfMountID:], d.Inode)

	return data, nil
}

func (d *Dentry) UnmarshalBinary(data []byte) error {
	d.MountID = binary.NativeEndian.Uint64(data[:])
	d.Inode = binary.NativeEndian.Uint32(data[unsafe.Sizeof(d.MountID):])
	return nil
}

func (d Dentry) Sizeof() uint32 {
	return 16
}

type IPPort struct {
	IP   uint32
	Port uint32
}

// TODO: generate unmarshaller + marshaller based on tag
func (d *IPPort) MarshalBinary() ([]byte, error) {
	sizeOfIP := unsafe.Sizeof(d.IP)
	data := make([]byte, d.Sizeof())

	binary.NativeEndian.PutUint32(data, d.IP)
	binary.NativeEndian.PutUint32(data[sizeOfIP:], d.Port)

	return data, nil
}

func (d *IPPort) UnmarshalBinary(data []byte) error {
	d.IP = binary.NativeEndian.Uint32(data[:])
	d.Port = binary.NativeEndian.Uint32(data[unsafe.Sizeof(d.IP):])
	return nil
}

func (d IPPort) Sizeof() uint32 {
	return 8
}

func runProg(t *testing.T, prog *Program, pre func(vm *VM), post func(vm *VM, output string)) {
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
			"map_array": {
				Name:       "map_array",
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 10,
			},
			"map_hash": {
				Name:       "map_hash",
				Type:       ebpf.LRUHash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 10,
			},
			"map_dentry": {
				Name:       "map_dentry",
				Type:       ebpf.LRUHash,
				KeySize:    4,
				ValueSize:  Dentry{}.Sizeof(),
				MaxEntries: 10,
			},
			"map_prog": {
				Name:       "map_prog",
				Type:       ebpf.ProgramArray,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 10,
			},
			"map_text": {
				Name:       "map_text",
				Type:       ebpf.Array,
				KeySize:    4,
				ValueSize:  16,
				MaxEntries: 10,
			},
			"map_ip": {
				Name:       "map_ip",
				Type:       ebpf.LRUHash,
				KeySize:    4,
				ValueSize:  IPPort{}.Sizeof(),
				MaxEntries: 10,
			},
		},
	}

	vm := NewVM(spec, Opts{Fncs: fncs, Logger: suggar})
	for k := range spec.Maps {
		_, err = vm.LoadMap(k)
		assert.Nil(t, err)
	}

	if pre != nil {
		pre(vm)
	}

	var ctx StdContext
	code, err := vm.RunProgram(&ctx, "test/printk")
	assert.Zero(t, code)
	assert.Nil(t, err)

	post(vm, printed)
}

func TestBuilderPrintk(t *testing.T) {
	t.Run("printk", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(55))
		var2 := builder.NewVarV(uint32(88))
		var3 := builder.NewVarV("test")
		builder.Printk("this is a printk test, values: %d %d %s", var1, var2, var3)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "this is a printk test, values: 55 88 test", output)
		})
	})

}

func TestBuilderCond(t *testing.T) {
	t.Run("if-then-else-ok", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.True(),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("if-then-else-ko", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.False(),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("if-then-else-empty-then-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.True(),
			func() {
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "", output)
		})
	})

	t.Run("if-then-else-empty-then-2", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.False(),
			func() {
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("if-then-else-empty", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.True(),
			func() {
			},
			func() {
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
		})
	})

	t.Run("if-then-else-no-else", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.True(),
			func() {
				builder.Printk("ok")
			},
			func() {
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("if-then-else-nested-ok", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.True(),
			func() {
				builder.IfThenElse(
					builder.True(),
					func() {
						builder.Printk("ok")
					},
					nil,
				)
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("if-then-else-nested-ko", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.True(),
			func() {
				builder.IfThenElse(
					builder.False(),
					func() {
						builder.Printk("ok")
					},
					func() {
						builder.Printk("ko")
					},
				)
			},
			func() {
				builder.Printk("no-called")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("equal-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(44))

		builder.IfThenElse(
			builder.Equal(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("equal-ok-2", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))

		builder.IfThenElse(
			builder.Equal(var1, uint32(44)),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("equal-ok-3", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint64(44444444444))

		builder.IfThenElse(
			builder.Equal(var1, uint64(44444444444)),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("equal-ok-4", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint64(44444444444))
		var2 := builder.NewVarV(uint64(44444444444))

		builder.IfThenElse(
			builder.Equal(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("equal-ko-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(66))

		builder.IfThenElse(
			builder.Equal(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("equal-ko-2", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))

		builder.IfThenElse(
			builder.Equal(var1, uint32(66)),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.And(builder.True(), builder.True()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("and-ko-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.And(builder.True(), builder.False()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-ko-2", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.And(builder.True(), builder.True(), builder.False()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-ko-3", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.And(builder.False(), builder.True(), builder.False()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("and-equal-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(66))

		builder.IfThenElse(
			builder.And(builder.Equal(var1, uint32(44)), builder.Equal(var2, uint32(66))),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("and-equal-ko-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(66))

		builder.IfThenElse(
			builder.And(builder.Equal(var1, uint32(44)), builder.Equal(var2, uint32(77))),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("or-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.Or(builder.False(), builder.True()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("or-ok-2", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.Or(builder.True(), builder.False()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("or-ko-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		builder.IfThenElse(
			builder.Or(builder.False(), builder.False()),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("or-equal-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(66))

		builder.IfThenElse(
			builder.Or(builder.Equal(var1, uint32(44)), builder.Equal(var2, uint32(77))),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("or-equal-ko-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(66))

		builder.IfThenElse(
			builder.Or(builder.Equal(var1, uint32(88)), builder.Equal(var2, uint32(77))),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("greater-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(45))
		var2 := builder.NewVarV(uint32(44))

		builder.IfThenElse(
			builder.Greater(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("greater-equal-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(44))

		builder.IfThenElse(
			builder.GreaterEqual(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("lesser-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(45))

		builder.IfThenElse(
			builder.Lesser(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("lesser-equal-ok-1", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV(uint32(44))
		var2 := builder.NewVarV(uint32(44))

		builder.IfThenElse(
			builder.LesserEqual(var1, var2),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})
}

func TestBuilderStrCmp(t *testing.T) {
	t.Run("strcmp-static-ok", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV("test123")

		builder.IfThenElse(
			builder.StrStaticCmp(var1, "test123"),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("strcmp-static-ko", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV("test123")

		builder.IfThenElse(
			builder.StrStaticCmp(var1, "test567"),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("strcmp-ok", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV("test123")
		var2 := builder.NewVarV("test123")

		builder.IfThenElse(
			builder.StrCmp(var1, var2, 30),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("strcmp-ko", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		var1 := builder.NewVarV("test123")
		var2 := builder.NewVarV("test567")

		builder.IfThenElse(
			builder.StrCmp(var1, var2, 30),
			func() {
				builder.Printk("ok")
			},
			func() {
				builder.Printk("ko")
			},
		)
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, nil, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})
}

func TestBuilderMap(t *testing.T) {
	t.Run("map-lookup", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_array", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		builder.Printk("value: %d", valuePtr.Deref(UInt32Type, 0))

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			updated, err := vm.Map("map_array").Update(uint32(1), uint32(44), BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "value: 44", output)
		})
	})

	t.Run("map-update", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(2))
		value := builder.NewVarV(uint32(66))
		ret := builder.NewVarV(int32(-1))

		builder.MapUpdate("map_array", key, value, ret, BPF_ANY)
		builder.IfThenElse(builder.NotEqual(ret, int32(0)),
			func() {
				builder.Return(0)
			}, nil)

		valuePtr := builder.NewPtrVar()
		builder.MapLookup("map_array", key, valuePtr)

		builder.Printk("value: %d", valuePtr.Deref(UInt32Type, 0))

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
		}, func(_ *VM, output string) {
			assert.Equal(t, "value: 66", output)
		})
	})

	t.Run("map-delete", func(t *testing.T) {
		var prog Program
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(2))
		value := builder.NewVarV(uint32(66))
		ret := builder.NewVarV(int32(-1))

		builder.MapUpdate("map_hash", key, value, ret, BPF_ANY)
		builder.IfThenElse(builder.NotEqual(ret, uint32(0)),
			func() {
				builder.Return(0)
			}, nil)

		valuePtr := builder.NewPtrVar()
		builder.MapLookup("map_hash", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		builder.Printk("value: %d", valuePtr.Deref(UInt32Type, 0))

		builder.MapDelete("map_hash", key, ret)
		builder.IfThenElse(builder.NotEqual(ret, uint32(0)),
			func() {
				builder.Return(0)
			}, nil)

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
		}, func(vm *VM, output string) {
			assert.Equal(t, "value: 66", output)

			data, err := vm.Map("map_hash").LookupBytes(uint32(2))
			assert.NoError(t, err)
			assert.Nil(t, data)
		})
	})
}

func TestBuilderMarshal(t *testing.T) {
	t.Run("map-lookup", func(t *testing.T) {
		var (
			prog   Program
			dentry = Dentry{
				MountID: 108,
				Inode:   90,
			}
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_dentry", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		mountID := valuePtr.Deref(UInt64Type, 0)
		inode := valuePtr.Deref(UInt32Type, UInt64Type.Sizeof())

		builder.IfThenElse(builder.And(
			builder.Equal(mountID, uint64(108)), builder.Equal(inode, uint32(90))),
			func() {
				builder.Printk("mount_id: %d, inode: %d", mountID, inode)
			},
			nil,
		)

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			updated, err := vm.Map("map_dentry").Update(uint32(1), &dentry, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "mount_id: 108, inode: 90", output)
		})
	})
}

func TestBuilderRawStrCmp(t *testing.T) {
	t.Run("raw-str", func(t *testing.T) {
		var (
			prog Program
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_text", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		text := make([]byte, 16)
		copy(text, "abcdef")

		for i, c := range text {
			v := valuePtr.Deref(UInt8Type, i)
			builder.IfThenElse(
				builder.NotEqual(v, uint8(c)),
				func() {
					builder.Return(0)
				},
				nil,
			)
			builder.FreeVar(v)
		}
		builder.Printk("ok")

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			updated, err := vm.Map("map_text").Update(uint32(1), text, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})
}

func TestBuilderStrIn(t *testing.T) {
	t.Run("str-in-ok", func(t *testing.T) {
		var (
			prog Program
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_text", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		builder.IfThenElse(builder.StrIn(valuePtr, "aaa", "bbb", "abcdef"), func() {
			builder.Printk("ok")
		}, nil)

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			text := make([]byte, 16)
			copy(text, "abcdef")

			updated, err := vm.Map("map_text").Update(uint32(1), text, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("str-in-ko", func(t *testing.T) {
		var (
			prog Program
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_text", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		builder.IfThenElse(builder.StrIn(valuePtr, "aaa", "bbb", "ccc"), func() {
			builder.Printk("ok")
			builder.Return(0)
		}, nil)

		builder.Printk("ko")
		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			text := make([]byte, 16)
			copy(text, "abcdef")

			updated, err := vm.Map("map_text").Update(uint32(1), text, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})

	t.Run("str-not-in-ok", func(t *testing.T) {
		var (
			prog Program
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_text", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		builder.IfThenElse(builder.Not(builder.StrIn(valuePtr, "aaa", "bbb", "abcdef")), func() {
			builder.Printk("ko")
		}, func() {
			builder.Printk("ok")
		})

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			text := make([]byte, 16)
			copy(text, "abcdef")

			updated, err := vm.Map("map_text").Update(uint32(1), text, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})
}

func TestBuilderTailCall(t *testing.T) {
	t.Run("call-ok", func(t *testing.T) {
		var (
			progEntry Program
			progExit  Program
		)
		progEntryBuilder := progEntry.Edit(ProgramBuilderOpts{})

		const (
			progIdx uint32 = 1
		)

		ctx := progEntryBuilder.NewCtxVar()

		value := progEntryBuilder.NewVarV(uint32(1))
		ret := progEntryBuilder.NewVarV(int32(-1))

		progEntryBuilder.IfThenElse(progEntryBuilder.Equal(value, uint32(1)),
			func() {
				progEntryBuilder.TailCall(ctx, "map_prog", progIdx, ret)
			},
			nil,
		)

		progEntryBuilder.Return(0)

		err := progEntryBuilder.Commit()
		require.Nil(t, err)

		progExitBuilder := progExit.Edit(ProgramBuilderOpts{})
		progExitBuilder.Printk("ok")
		progExitBuilder.Return(0)

		err = progExitBuilder.Commit()
		require.Nil(t, err)

		runProg(t, &progEntry, func(vm *VM) {
			progExitSpec := ebpf.ProgramSpec{
				Name:         "test/exit",
				SectionName:  "test/exit",
				Type:         ebpf.Kprobe,
				Instructions: progExit.Instructions(),
			}
			fd := vm.AddProgram(&progExitSpec)

			updated, err := vm.Map("map_prog").Update(progIdx, fd, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})

	t.Run("call-ok-var", func(t *testing.T) {
		var (
			progEntry Program
			progExit  Program
		)
		progEntryBuilder := progEntry.Edit(ProgramBuilderOpts{})

		const (
			progIdx uint32 = 1
		)

		ctx := progEntryBuilder.NewCtxVar()

		value := progEntryBuilder.NewVarV(progIdx)
		ret := progEntryBuilder.NewVarV(int32(-1))

		progEntryBuilder.IfThenElse(progEntryBuilder.Equal(value, uint32(1)),
			func() {
				progEntryBuilder.TailCall(ctx, "map_prog", value, ret)
			},
			nil,
		)

		progEntryBuilder.Return(0)

		err := progEntryBuilder.Commit()
		require.Nil(t, err)

		progExitBuilder := progExit.Edit(ProgramBuilderOpts{})
		progExitBuilder.Printk("ok")
		progExitBuilder.Return(0)

		err = progExitBuilder.Commit()
		require.Nil(t, err)

		runProg(t, &progEntry, func(vm *VM) {
			progExitSpec := ebpf.ProgramSpec{
				Name:         "test/exit",
				SectionName:  "test/exit",
				Type:         ebpf.Kprobe,
				Instructions: progExit.Instructions(),
			}
			fd := vm.AddProgram(&progExitSpec)

			updated, err := vm.Map("map_prog").Update(progIdx, fd, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ok", output)
		})
	})
}

func ipRange(cidr string) (uint32, uint32) {
	firstIP, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0
	}

	ones, bits := ipNet.Mask.Size()
	num := uint32(1 << (bits - ones))

	first := binary.BigEndian.Uint32(firstIP.To4())

	return first, first + num - 1
}

func TestBuilderIPRange(t *testing.T) {
	t.Run("ip-range-ok-1", func(t *testing.T) {
		var (
			ip32   = binary.BigEndian.Uint32(net.ParseIP("192.168.1.18").To4())
			prog   Program
			ipport = IPPort{
				IP:   ip32,
				Port: 80,
			}
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_ip", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		ip := valuePtr.Deref(UInt32Type, 0)
		port := valuePtr.Deref(UInt32Type, UInt32Type.Sizeof())

		ipFirst, ipLast := ipRange("192.168.1.0/24")

		builder.IfThenElse(builder.And(
			builder.GreaterEqual(ip, int64(ipFirst)), // force 64 to avoid int32 signed overflow
			builder.LesserEqual(ip, int64(ipLast)),   // force 64 to avoid int32 signed overflow
			builder.Equal(port, 80),
		),
			func() {
				builder.Printk("ip in range: %d, port: %d", ip, port)
			},
			nil,
		)

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			updated, err := vm.Map("map_ip").Update(uint32(1), &ipport, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, fmt.Sprintf("ip in range: %d, port: 80", ip32), output)
		})
	})

	t.Run("ip-range-ok-2", func(t *testing.T) {
		var (
			ip32   = binary.BigEndian.Uint32(net.ParseIP("192.168.1.18").To4())
			prog   Program
			ipport = IPPort{
				IP:   ip32,
				Port: 80,
			}
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_ip", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		ip := valuePtr.Deref(UInt32Type, 0)
		port := valuePtr.Deref(UInt32Type, UInt32Type.Sizeof())

		ip1First, ip1Last := ipRange("192.168.0.0/24")
		ip2First, ip2Last := ipRange("192.168.1.0/24")

		match1 := builder.And(
			builder.GreaterEqual(ip, int64(ip1First)), // force 64 to avoid int32 signed overflow
			builder.LesserEqual(ip, int64(ip1Last)),   // force 64 to avoid int32 signed overflow
			builder.Equal(port, 80),
		)

		match2 := builder.And(
			builder.GreaterEqual(ip, int64(ip2First)), // force 64 to avoid int32 signed overflow
			builder.LesserEqual(ip, int64(ip2Last)),   // force 64 to avoid int32 signed overflow
			builder.Equal(port, 80),
		)

		builder.IfThenElse(builder.Or(match1, match2),
			func() {
				builder.Printk("ip in range: %d, port: %d", ip, port)
			},
			nil,
		)

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			updated, err := vm.Map("map_ip").Update(uint32(1), &ipport, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, fmt.Sprintf("ip in range: %d, port: 80", ip32), output)
		})
	})

	t.Run("ip-range-ko-1", func(t *testing.T) {
		var (
			ip32   = binary.BigEndian.Uint32(net.ParseIP("192.168.1.18").To4())
			prog   Program
			ipport = IPPort{
				IP:   ip32,
				Port: 80,
			}
		)
		builder := prog.Edit(ProgramBuilderOpts{})

		key := builder.NewVarV(uint32(1))
		valuePtr := builder.NewPtrVar()

		builder.MapLookup("map_ip", key, valuePtr)
		builder.IfThenElse(builder.IsNull(valuePtr), func() {
			builder.Return(0)
		}, nil)

		ip := valuePtr.Deref(UInt32Type, 0)
		port := valuePtr.Deref(UInt32Type, UInt32Type.Sizeof())

		ip1First, ip1Last := ipRange("192.168.0.0/24")
		ip2First, ip2Last := ipRange("192.168.1.0/24")

		match1 := builder.And(
			builder.GreaterEqual(ip, int64(ip1First)), // force 64 to avoid int32 signed overflow
			builder.LesserEqual(ip, int64(ip1Last)),   // force 64 to avoid int32 signed overflow
			builder.Equal(port, 80),
		)

		match2 := builder.And(
			builder.GreaterEqual(ip, int64(ip2First)), // force 64 to avoid int32 signed overflow
			builder.LesserEqual(ip, int64(ip2Last)),   // force 64 to avoid int32 signed overflow
			builder.Equal(port, 8080),
		)

		builder.IfThenElse(builder.Or(match1, match2),
			nil,
			func() {
				builder.Printk("ko")
			},
		)

		builder.Return(0)

		err := builder.Commit()
		require.Nil(t, err)

		runProg(t, &prog, func(vm *VM) {
			updated, err := vm.Map("map_ip").Update(uint32(1), &ipport, BPF_ANY)
			assert.True(t, updated)
			assert.Nil(t, err)
		}, func(_ *VM, output string) {
			assert.Equal(t, "ko", output)
		})
	})
}
