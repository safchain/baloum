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
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type Program struct {
	Type         ebpf.ProgramType
	Instructions asm.Instructions
}

func (p *Program) ResolveReferences() {
	symbols := make(map[string]int)

	for offset, ins := range p.Instructions {
		if symbol := ins.Symbol(); symbol != "" {
			symbols[symbol] = offset
		}
	}

	for i, ins := range p.Instructions {
		if ref := ins.Reference(); ref != "" {

			offset, exists := symbols[ref]
			if exists {
				ins.Offset = int16(offset - i)
				p.Instructions[i] = ins
			}
		}
	}
}
