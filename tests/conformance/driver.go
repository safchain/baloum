package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/safchain/baloum/pkg/baloum"
)

const TEST_RUN_SECTION = "test_run"

func main() {
	program, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	programByteCode, err := decode_hexa(string(program))
	if err != nil {
		panic(err)
	}

	var memoryBytes []byte
	if len(os.Args) > 1 {
		memory := os.Args[1]
		mb, err := decode_hexa(memory)
		if err != nil {
			panic(err)
		}
		memoryBytes = mb
	}

	var instructions asm.Instructions
	if err := instructions.Unmarshal(bytes.NewReader(programByteCode), binary.LittleEndian); err != nil {
		panic(err)
	}

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			TEST_RUN_SECTION: {
				Instructions: instructions,
				SectionName:  TEST_RUN_SECTION,
			},
		},
	}

	vm := baloum.NewVM(spec, baloum.Opts{})

	code, err := vm.RunProgramWithRawMemory(memoryBytes, TEST_RUN_SECTION, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", uint64(code))
}

func decode_hexa(in string) ([]byte, error) {
	res := make([]byte, 0)

	for _, word := range strings.Split(in, " ") {
		word = strings.TrimSpace(word)

		b, err := hex.DecodeString(word)
		if err != nil {
			return nil, err
		}
		res = append(res, b...)
	}

	return res, nil
}
