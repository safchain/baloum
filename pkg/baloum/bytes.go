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
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

var ByteOrder binary.ByteOrder

func ToBytes(data interface{}, size int) ([]byte, error) {
	if size == 0 {
		return nil, errors.New("data size error")
	}

	b := make([]byte, size)

	switch t := data.(type) {
	case uint8:
		b[0] = t
	case uint16:
		if size != 2 {
			return nil, errors.New("data size error : size mismatch")
		}
		ByteOrder.PutUint16(b, t)
	case uint32:
		if size != 4 {
			return nil, errors.New("data size error : size mismatch")
		}
		ByteOrder.PutUint32(b, t)
	case uint64:
		if size != 8 {
			return nil, errors.New("data size error : size mismatch")
		}
		ByteOrder.PutUint64(b, t)
	case []byte:
		if len(t) != size {
			return nil, errors.New("data size error : size mismatch")
		}
		copy(b, t)
	default:
		return nil, errors.New("data size error : unknown type")
	}
	return b, nil
}

// GetHostByteOrder guesses the hosts byte order
func GetHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

func UnmarshalCtx(data []byte) [16]uint16 {
	fmt.Printf("ZZZZZZ: %+v\n", data)
	return [16]uint16{}
}

func init() {
	ByteOrder = GetHostByteOrder()
}
