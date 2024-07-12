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

type SymbolType = string

const (
	JumpSymbolType       SymbolType = "jmp"
	BreakpointSymbolType SymbolType = "breakpoint"
)

// see : https://docs.kernel.org/bpf/verifier.html?highlight=ebpf%20tc

type Program struct {
	insts asm.Instructions
}

func (p *Program) Edit(opts ProgramBuilderOpts) *ProgramBuilder {
	return NewProgramBuilder(p, opts)
}

func (p *Program) PrintInstructions() {
	fmt.Printf("%+v\n", p.insts)
}

func (p *Program) Prepare(instLimit int) error {
	if err := p.ResolveReferences(); err != nil {
		return err
	}

	if err := p.VerifyDag(); err != nil {
		return err
	}

	if len(p.insts) > instLimit {
		return errors.New("instruction limit reached")
	}

	return nil
}

// VerifyDag super naive Dag verification
func (p *Program) VerifyDag() error {
	var offsets []int

	for i := 0; i < len(p.insts); i++ {
		inst := p.insts[i]

		if slices.Contains(offsets, i) {
			return fmt.Errorf("not a dag, inst #%d: %v", i, inst)
		}
		offsets = append(offsets, i)

		if inst.OpCode == asm.Ja.Op(asm.ImmSource) {
			i += int(inst.Offset)
		}
	}

	return nil
}

func (p *Program) ResolveReferences() error {
	symbols := make(map[string]int)

	for offset, ins := range p.insts {
		if symbol := ins.Symbol(); symbol != "" {
			symbols[symbol] = offset
		}
	}

	for i, ins := range p.insts {
		if ref := ins.Reference(); ref != "" {
			offset, exists := symbols[ref]
			if exists {
				var inc int

				// correct with size of instruction size
				delta := offset - i - 1
				if delta > 0 {
					for j := 0; j != delta; j++ {
						if p.insts[i+j].Size() > 8 {
							inc++
						}
					}
				} else {
					for j := 0; j != delta; j-- {
						if p.insts[i+j].Size() > 8 {
							inc--
						}
					}
				}

				ins.Offset = int16(delta + inc)
				p.insts[i] = ins
			}
		}
	}

	return nil
}

func (p *Program) Append(insts ...interface{}) {
	p.insts = append(p.insts, Instructions(insts...)...)
}

func (p *Program) Instructions() asm.Instructions {
	return p.insts
}

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
