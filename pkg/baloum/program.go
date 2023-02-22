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

	"github.com/cilium/ebpf/asm"
)

func ResolveReferences(insts asm.Instructions) error {
	symbols := make(map[string]int)

	for offset, ins := range insts {
		if symbol := ins.Symbol(); symbol != "" {
			symbols[symbol] = offset
		}
	}

	for i, ins := range insts {
		if ref := ins.Reference(); ref != "" {
			offset, exists := symbols[ref]
			if exists {
				delta := offset - i - 1
				if delta < 0 {
					return fmt.Errorf("backward branch ins %d : %v", i, ins)
				}
				// correct with size of instruction size
				var inc int
				for j := 0; j != delta; j++ {
					if insts[i+j].Size() > 8 {
						inc++
					}
				}
				ins.Offset = int16(delta + inc)
				insts[i] = ins
			}
		}
	}

	return nil
}
