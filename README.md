# Baloum - Userspace eBPF virtual machine

![build](https://github.com/safchain/baloum/actions/workflows/unittests.yml/badge.svg) ![conformance](https://github.com/safchain/baloum/actions/workflows/conformance.yml/badge.svg)

## About

Baloum is a eBPF virtual machine which runs in userspace. The goal is to provide a userspace environment for eBPF which can be used as a unit test platform for eBPF.

## Getting Started

### Install

```shell
go get github.com/safchain/baloum
```

### Examples

Here an example of how to run an eBPF program.

```go
package main

import (
	"github.com/cilium/ebpf"
)

func main() {
	reader, err := os.Open("./ebpf/bin/ex1.o")
	if err != nil {
		panic(err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		panic(err)
	}

	vm := baloum.NewVM(spec, baloum.Opts{Fncs: fncs, Logger: suggar})

	var ctx baloum.StdContext

	code, err := vm.RunProgram(&ctx, "test/ex1")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Result: %d\n", code)
}

```

More complete examples can be found under examples/](examples/).

## Coverage

## Conformance

Baloum make use of the [Alan-Jowett/bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) conformance test suite to validate the eBPF support.

### Maps

| Type                                          | supported |
|-----------------------------------------------|-----------|
|	BPF_MAP_TYPE_HASH                       |    ✅     |
|	BPF_MAP_TYPE_ARRAY                      |    ✅     |
|	BPF_MAP_TYPE_PROG_ARRAY                 |    ✅     |
|	BPF_MAP_TYPE_PERF_EVENT_ARRAY           |    ✅     |
|	BPF_MAP_TYPE_PERCPU_HASH                |    ❌     |
|	BPF_MAP_TYPE_PERCPU_ARRAY               |    ✅     |
|	BPF_MAP_TYPE_STACK_TRACE                |    ❌     |
|	BPF_MAP_TYPE_CGROUP_ARRAY               |    ❌     |
|	BPF_MAP_TYPE_LRU_HASH                   |    ✅     |
|	BPF_MAP_TYPE_LRU_PERCPU_HASH            |    ❌     |
|	BPF_MAP_TYPE_LPM_TRIE                   |    ❌     |
|	BPF_MAP_TYPE_ARRAY_OF_MAPS              |    ❌     |
|	BPF_MAP_TYPE_HASH_OF_MAPS               |    ❌     |
|	BPF_MAP_TYPE_DEVMAP                     |    ❌     |
|	BPF_MAP_TYPE_SOCKMAP                    |    ❌     |
|	BPF_MAP_TYPE_CPUMAP                     |    ❌     |
|	BPF_MAP_TYPE_XSKMAP                     |    ❌     |
|	BPF_MAP_TYPE_SOCKHASH                   |    ❌     |
|	BPF_MAP_TYPE_CGROUP_STORAGE             |    ❌     |
|	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY        |    ❌     |
|	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE      |    ❌     |
|	BPF_MAP_TYPE_QUEUE                      |    ❌     |
|	BPF_MAP_TYPE_STACK                      |    ❌     |
|	BPF_MAP_TYPE_SK_STORAGE                 |    ❌     |
|	BPF_MAP_TYPE_DEVMAP_HASH                |    ❌     |
|	BPF_MAP_TYPE_STRUCT_OPS                	|    ❌     |
|	BPF_MAP_TYPE_RINGBUF                    |    ❌     |
|	BPF_MAP_TYPE_INODE_STORAGE              |    ❌     |
|	BPF_MAP_TYPE_TASK_STORAGE               |    ❌     |
|	BPF_MAP_TYPE_BLOOM_FILTER               |    ❌     |

### Helpers

Supported helpers are declared in the following [file](https://github.com/safchain/baloum/blob/main/pkg/baloum/fncs.go). New helpers implementation can be defined through options.

## Licence

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
