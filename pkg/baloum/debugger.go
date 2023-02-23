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
	"os"
	"runtime"

	"github.com/cilium/ebpf/asm"
	"github.com/peterh/liner"
)

type DebugCommand string

const (
	NextCommand           DebugCommand = "n"
	ContinueCommand       DebugCommand = "c"
	PrintStackCommand     DebugCommand = "ps"
	PrintRegistersCommand DebugCommand = "pr"
	PrintCommand          DebugCommand = "p"
)

type Debugger struct {
	Enabled bool
	lastCmd string
	liner   *liner.State
}

func (d *Debugger) dumpRegister(vm *VM) {
	for i, v := range vm.regs {
		if i > 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("R%d: %v", i, v)
	}
	fmt.Println()
}

func (d *Debugger) dumpStack(vm *VM) {
	var notFirst bool
	for i, b := range vm.stack {
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

func (d *Debugger) ObserveInst(vm *VM, pc int, inst *asm.Instruction) {
	if d.liner == nil {
		d.liner = liner.NewLiner()
		runtime.SetFinalizer(d, func(i interface{}) {
			i.(*Debugger).liner.Close()
		})
	}

	d.Enabled = d.Enabled || inst.Symbol() == "debugger"
	if !d.Enabled {
		return
	}

	fmt.Fprintf(os.Stdout, "%d: %v\n", pc, inst)

LOOP:
	debugCmd, err := d.liner.Prompt("> ")
	if err != nil {
		fmt.Println()
		d.liner.Close()
		os.Exit(0)
	}
	if debugCmd == "" {
		debugCmd = d.lastCmd
	}
	d.lastCmd = debugCmd
	d.liner.AppendHistory(debugCmd)

	switch DebugCommand(debugCmd) {
	case NextCommand:
	case ContinueCommand:
		d.Enabled = false
	case PrintStackCommand:
		d.dumpStack(vm)
		goto LOOP
	case PrintRegistersCommand:
		d.dumpRegister(vm)
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
