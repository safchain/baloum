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

package debugger

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/peterh/liner"
	"github.com/safchain/baloum/pkg/baloum"
)

type DebugCommand string

const (
	NextCommand           DebugCommand = "n"
	ContinueCommand       DebugCommand = "c"
	PrintStackCommand     DebugCommand = "ps"
	PrintRegistersCommand DebugCommand = "pr"
	PrintVariableCommand  DebugCommand = "pv"
	PrintMap              DebugCommand = "pm"
	PrintCommand          DebugCommand = "p"
	PrintBacktraceCommand DebugCommand = "bt"
)

type VariableReader struct {
	Size uint64
	Read func(bytes []byte) interface{}
}

type BTInst struct {
	PC   int
	Inst asm.Instruction
}

type Debugger struct {
	Enabled        bool
	VariableReader map[string]VariableReader
	lastCmd        string
	state          *liner.State
	backtrace      []BTInst
}

func NewDebugger(enabled bool, variableReaders map[string]VariableReader) *Debugger {
	return &Debugger{
		Enabled:        enabled,
		VariableReader: variableReaders,
	}
}

func (d *Debugger) dumpRegister(vm *baloum.VM) {
	for i, v := range vm.Regs() {
		if i > 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("R%d: %v", i, v)
	}
	fmt.Println()
}

func (d *Debugger) dumpBytes(bytes []byte) {
	var notFirst bool
	for i, b := range bytes {
		if i%16 == 0 {
			if notFirst {
				fmt.Println()
			}
			notFirst = true
			fmt.Printf("%3d    ", i)
		}
		fmt.Printf("%03d ", b)
	}
	fmt.Println()
}

func (d *Debugger) dumpStack(vm *baloum.VM) {
	d.dumpBytes(vm.Stack())
}

func (d *Debugger) printMap(vm *baloum.VM, args ...string) {
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "syntax error: pm <mapname>\n")
		return
	}

	_map := vm.GetMapByName(args[0])
	if _map == nil {
		fmt.Fprintf(os.Stderr, "map not found")
		return
	}

	it, err := _map.Iterator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "map lookup error")
		return
	}

	for {
		key, value, exists := it.Next()
		if !exists {
			break
		}

		fmt.Printf("key:\n")
		d.dumpBytes(key)

		fmt.Printf("value:\n")
		d.dumpBytes(value)
	}
}

func (d *Debugger) printVariable(vm *baloum.VM, args ...string) {
	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "syntax error: pr <varname> <addr|register>\n")
		return
	}
	name, addr := args[0], args[1]

	reader, exists := d.VariableReader[name]
	if !exists {
		fmt.Fprintf(os.Stderr, "variable unknown\n")
		return
	}

	var ptr uint64

	regs := vm.Regs()

	if addr[0] == 'R' || addr[0] == 'r' {
		reg, err := strconv.Atoi(addr[1:])
		if err != nil || reg >= len(regs) {
			fmt.Fprintf(os.Stderr, "register unknown\n")
			return
		}
		ptr = regs[reg]
	} else {
		value, err := strconv.Atoi(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "incorrect address\n")
			return
		}
		ptr = uint64(value)
	}

	bytes, err := vm.GetBytes(ptr, reader.Size)
	if err != nil {
		fmt.Fprintf(os.Stderr, "address incorrect\n")
		return
	}

	fmt.Printf(">> %v\n", reader.Read(bytes))
}

func (d *Debugger) printBacktrace(vm *baloum.VM) {
	for _, bt := range d.backtrace {
		fmt.Printf("%d: %v\n", bt.PC, bt.Inst)
	}
}

func (d *Debugger) Close() {
	if d.state != nil {
		d.state.Close()
	}
}

func (d *Debugger) ObserveInst(vm *baloum.VM, pc int, inst *asm.Instruction) {
	d.backtrace = append(d.backtrace, BTInst{PC: pc, Inst: *inst})

	if d.state == nil {
		d.state = liner.NewLiner()
	}

	d.Enabled = d.Enabled || strings.HasPrefix(inst.Symbol(), "debugger")
	if !d.Enabled {
		return
	}

	fmt.Printf("%d: %v [%s]\n", pc, inst, inst.Symbol())

LOOP:
	debugCmd, err := d.state.Prompt("> ")
	if err != nil {
		fmt.Println()
		d.state.Close()
		os.Exit(0)
	}
	if debugCmd == "" {
		debugCmd = d.lastCmd
	}
	d.lastCmd = debugCmd
	d.state.AppendHistory(debugCmd)

	els := strings.Split(debugCmd, " ")
	cmd, args := DebugCommand(els[0]), els[1:]

	switch DebugCommand(cmd) {
	case NextCommand:
	case ContinueCommand:
		d.Enabled = false
	case PrintStackCommand:
		d.dumpStack(vm)
		goto LOOP
	case PrintRegistersCommand:
		d.dumpRegister(vm)
		goto LOOP
	case PrintVariableCommand:
		d.printVariable(vm, args...)
		goto LOOP
	case PrintBacktraceCommand:
		d.printBacktrace(vm)
		goto LOOP
	case PrintMap:
		d.printMap(vm, args...)
		goto LOOP
	case PrintCommand:
		fmt.Println("Registers:")
		d.dumpRegister(vm)
		fmt.Println("Stack:")
		d.dumpStack(vm)
		goto LOOP
	default:
		fmt.Fprintf(os.Stdout, "command unknown !\n")
		goto LOOP
	}
}
