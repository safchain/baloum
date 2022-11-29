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
	"log"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestMapArray64(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_map_array.o")
	if err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Fatal(err)
	}

	vm := NewVM(spec, Opts{Logger: suggar})

	var ctx Context
	code, err := vm.RunProgram(ctx, "test/array64")
	assert.Zero(t, code)
	assert.Nil(t, err)

	data, err := vm.Map("cache64").Lookup(uint64(4))
	assert.Nil(t, err)
	assert.Equal(t, uint64(44), ByteOrder.Uint64(data))
}

func TestMapArray32(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_map_array.o")
	if err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		log.Fatal(err)
	}

	vm := NewVM(spec, Opts{Logger: suggar})

	var ctx Context
	code, err := vm.RunProgram(ctx, "test/array32")
	assert.Zero(t, code)
	assert.Nil(t, err)

	data, err := vm.Map("cache32").Lookup(uint32(4))
	assert.Nil(t, err)
	assert.Equal(t, uint32(44), ByteOrder.Uint32(data))
}
