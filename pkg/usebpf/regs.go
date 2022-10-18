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

package usebpf

import "errors"

const (
	REGS_NUM  = 11
	REGS_SIZE = REGS_NUM * 8
)

type Regs [REGS_NUM]uint64

func (r *Regs) Parse(data []byte) error {
	if len(data) < REGS_SIZE {
		return errors.New("not enough data")
	}

	var offset int
	for i := range r {
		r[i] = ByteOrder.Uint64(data[offset : offset+8])
		offset += 8
	}

	return nil
}

func (r *Regs) Bytes() []byte {
	data := make([]byte, REGS_SIZE)

	var offset int
	for _, reg := range r {
		ByteOrder.PutUint64(data[offset:offset+8], reg)
		offset += 8
	}

	return data
}
