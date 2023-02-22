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
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/asm"
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
	Enabled      bool
	lastDebugCmd DebugCommand
}

func (d *Debugger) ObserveInst(pc int, inst *asm.Instruction) {
	d.Enabled = d.Enabled || inst.Symbol() == "debugger"
	if !d.Enabled {
		return
	}

	fmt.Fprintf(os.Stdout, "%d: %v\n", pc, inst)
	fmt.Fprintf(os.Stdout, "> ")

LOOP:

	reader := bufio.NewReader(os.Stdin)
	cmd, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	debugCmd := DebugCommand(strings.TrimSuffix(cmd, "\n"))
	if debugCmd == "" {
		debugCmd = d.lastDebugCmd
	}

	switch debugCmd {
	case NextCommand:
	case ContinueCommand:
		d.Enabled = false
	case PrintStackCommand:
		fmt.Fprintf(os.Stdout, "Print stack\n")
	case PrintRegistersCommand:
		fmt.Fprintf(os.Stdout, "Print registers\n")
	case PrintCommand:
		fmt.Fprintf(os.Stdout, "Print\n")
	default:
		fmt.Fprintf(os.Stdout, "command unknown !")
		goto LOOP
	}
	d.lastDebugCmd = debugCmd
}
