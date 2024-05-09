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
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

func ToBytes(obj interface{}, size int) ([]byte, error) {
	if size == 0 {
		return nil, errors.New("data size error")
	}

	if m, ok := obj.(encoding.BinaryMarshaler); ok {
		b, err := m.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if len(b) != size {
			return nil, fmt.Errorf("data size error : size mismatch, %d vs %d", len(b), size)
		}
		return b, nil
	}

	b := make([]byte, size)

	switch t := obj.(type) {
	case int8:
		b[0] = byte(t)
	case uint8:
		b[0] = t
	case int16:
		if size != 2 {
			return nil, errors.New("data size error : size mismatch")
		}
		binary.NativeEndian.PutUint16(b, uint16(t))
	case uint16:
		if size != 2 {
			return nil, errors.New("data size error : size mismatch")
		}
		binary.NativeEndian.PutUint16(b, t)
	case int32:
		if size != 4 {
			return nil, errors.New("data size error : size mismatch")
		}
		binary.NativeEndian.PutUint32(b, uint32(t))
	case uint32:
		if size != 4 {
			return nil, errors.New("data size error : size mismatch")
		}
		binary.NativeEndian.PutUint32(b, t)
	case int64:
		if size != 8 {
			return nil, errors.New("data size error : size mismatch")
		}
		binary.NativeEndian.PutUint64(b, uint64(t))
	case uint64:
		if size != 8 {
			return nil, errors.New("data size error : size mismatch")
		}
		binary.NativeEndian.PutUint64(b, t)
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

func FromBytes(data []byte, obj interface{}) error {
	if m, ok := obj.(encoding.BinaryUnmarshaler); ok {
		return m.UnmarshalBinary(data)
	}

	switch t := obj.(type) {
	case *int8:
		*t = int8(data[0])
	case *uint8:
		*t = data[0]
	case *int16:
		if len(data) != 2 {
			return errors.New("data size error : size mismatch")
		}
		*t = int16(binary.NativeEndian.Uint16(data))
	case *uint16:
		if len(data) != 2 {
			return errors.New("data size error : size mismatch")
		}
		*t = binary.NativeEndian.Uint16(data)
	case *int32:
		if len(data) != 4 {
			return errors.New("data size error : size mismatch")
		}
		*t = int32(binary.NativeEndian.Uint32(data))
	case *uint32:
		if len(data) != 4 {
			return errors.New("data size error : size mismatch")
		}
		*t = binary.NativeEndian.Uint32(data)
	case *int64:
		if len(data) != 8 {
			return errors.New("data size error : size mismatch")
		}
		*t = int64(binary.NativeEndian.Uint64(data))
	case *uint64:
		if len(data) != 8 {
			return errors.New("data size error : size mismatch")
		}
		*t = binary.NativeEndian.Uint64(data)
	case []byte:
		if len(data) != len(t) {
			return errors.New("data size error : size mismatch")
		}
		copy(t, data)
	default:
		return errors.New("data size error : unknown type")
	}
	return nil
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
