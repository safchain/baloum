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
	"errors"
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/cilium/ebpf/asm"
)

// SymbolType is the type for the symbol type
type SymbolType = string

const (
	// JumpSymbolType is the type for the jump symbol
	JumpSymbolType SymbolType = "jmp"
	// BreakpointSymbolType is the type for the breakpoint symbol
	BreakpointSymbolType SymbolType = "breakpoint"
)

// see : https://docs.kernel.org/bpf/verifier.html?highlight=ebpf%20tc

// Program is the type for the program
type Program struct {
	insts asm.Instructions
}

// Edit returns a new program builder
func (p *Program) Edit(opts ProgramBuilderOpts) *ProgramBuilder {
	return NewProgramBuilder(p, opts)
}

// PrintInstructions prints the instructions
func (p *Program) PrintInstructions() {
	fmt.Printf("%+v\n", p.insts)
}

// Prepare prepares the program
func (p *Program) Prepare(instLimit int) error {
	insts := resolveSymbolReferences(p.insts)

	if err := VerifyDag(insts); err != nil {
		return err
	}

	if len(p.insts) > instLimit {
		return errors.New("instruction limit reached")
	}

	return nil
}

// VerifyDag super naive Dag verification
func VerifyDag(insts asm.Instructions) error {
	var offsets []int

	for i := 0; i < len(insts); i++ {
		inst := insts[i]

		if slices.Contains(offsets, i) {
			return fmt.Errorf("not a dag, inst #%d: %v", i, inst)
		}
		offsets = append(offsets, i)

		if inst.OpCode.Class().IsJump() {
			i += int(inst.Offset)
		}
	}

	return nil
}

// Append appends instructions to the program
func (p *Program) Append(insts ...interface{}) {
	p.insts = append(p.insts, Instructions(insts...)...)
}

// Instructions returns the instructions
func (p *Program) Instructions() asm.Instructions {
	return p.insts
}

// Instructions converts a list of instructions to an asm.Instructions
func Instructions(insts ...interface{}) asm.Instructions {
	var instructions asm.Instructions
	for _, inst := range insts {
		switch t := inst.(type) {
		case asm.Instruction:
			instructions = append(instructions, t)
		case []asm.Instruction:
			instructions = append(instructions, t...)
		case asm.Instructions:
			instructions = append(instructions, t...)
		}
	}
	return instructions
}
