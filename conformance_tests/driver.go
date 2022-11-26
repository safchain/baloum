package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/safchain/baloum/pkg/baloum"
	"go.uber.org/zap"
)

const TEST_RUN_SECTION = "test_run"

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	program := flag.String("program", "", "input program in hexa form")
	flag.Parse()

	memory := flag.Arg(0)

	fmt.Println(*program, memory)

	programByteCode, err := decode_hexa(*program)
	if err != nil {
		panic(err)
	}

	_, err = decode_hexa(memory)
	if err != nil {
		panic(err)
	}

	var instructions asm.Instructions
	if err := instructions.Unmarshal(bytes.NewReader(programByteCode), binary.LittleEndian); err != nil {
		panic(err)
	}

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			TEST_RUN_SECTION: {
				Instructions: instructions,
			},
		},
	}

	vm := baloum.NewVM(spec, baloum.Opts{Logger: suggar})

	var ctx baloum.Context
	code, err := vm.RunProgram(ctx, TEST_RUN_SECTION)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%x\n", code)
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
