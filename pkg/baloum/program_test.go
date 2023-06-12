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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStackAlloc(t *testing.T) {
	t.Run("success1", func(t *testing.T) {
		var prog Program

		addr, err := prog.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("full-one-block", func(t *testing.T) {
		var prog Program

		addr, err := prog.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)

		_, err = prog.StackAlloc(1)
		assert.NotNil(t, err)
	})

	t.Run("one-block-reuse", func(t *testing.T) {
		var prog Program

		addr, err := prog.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)

		prog.StackFree(addr)

		addr, err = prog.StackAlloc(512)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("two-blocks", func(t *testing.T) {
		var prog Program

		addr, err := prog.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-256), addr)

		addr, err = prog.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr)
	})

	t.Run("three-blocks-with-free", func(t *testing.T) {
		var prog Program

		addr1, err := prog.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-256), addr1)

		addr2, err := prog.StackAlloc(256)
		assert.Nil(t, err)
		assert.Equal(t, int16(-512), addr2)

		prog.StackFree(addr1)

		addr3, err := prog.StackAlloc(128)
		assert.Nil(t, err)
		assert.Equal(t, int16(-128), addr3)

		addr4, err := prog.StackAlloc(32)
		assert.Nil(t, err)
		assert.Equal(t, int16(-160), addr4)

		addr5, err := prog.StackAlloc(32)
		assert.Nil(t, err)
		assert.Equal(t, int16(-192), addr5)

		_, err = prog.StackAlloc(65)
		assert.NotNil(t, err)
	})
}
