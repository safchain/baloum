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
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestMapPerf(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	suggar := logger.Sugar()

	reader, err := os.Open("../../tests/ebpf/bin/test_map_perf.o")
	if err != nil {
		suggar.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		suggar.Fatal(err)
	}

	vm := NewVM(spec, Opts{Logger: suggar})

	var ctx StdContext
	code, err := vm.RunProgram(&ctx, "test/perf")
	assert.Zero(t, code)
	assert.Nil(t, err)

	events, err := vm.Map("events").Read()
	assert.Nil(t, err)

	data := <-events

	key := ByteOrder.Uint64(data[0:8])
	assert.Equal(t, uint64(123), key)

	value := ByteOrder.Uint64(data[8:16])
	assert.Equal(t, uint64(456), value)
}
