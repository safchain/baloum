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
	"errors"

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

// Bytes2String converts a byte slice to a string
func Bytes2String(data []byte) string {
	idx := bytes.IndexByte(data, 0)
	if idx == -1 {
		return string(data)
	}
	return string(data[0:uint64(idx)])
}

// ToInt32 converts a value to an int32
func ToInt32(value interface{}) (int32, error) {
	i, err := ToInt64(value)
	return int32(i), err
}

// ToInt64 converts a value to an int64
func ToInt64(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int8:
		return int64(v), nil
	case uint8:
		return int64(v), nil
	case int16:
		return int64(v), nil
	case uint16:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case uint32:
		return int64(v), nil
	case int64:
		return int64(v), nil
	case uint64:
		return int64(v), nil
	}
	return 0, errors.New("unknown type")
}
