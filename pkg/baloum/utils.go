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
	"bytes"

	"github.com/cilium/ebpf"
)

func progMatch(prog *ebpf.ProgramSpec, sections ...string) bool {
	if len(sections) > 0 {
		for _, name := range sections {
			if prog.SectionName == name {
				return true
			}
		}
	} else {
		return true
	}
	return false
}

func Bytes2String(data []byte) string {
	idx := bytes.IndexByte(data, 0)
	if idx == -1 {
		return string(data)
	}
	return string(data[0:uint64(idx)])
}
