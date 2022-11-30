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

func (ctx *StdContext) Bytes() []byte {
	data := make([]byte, 168)

	ByteOrder.PutUint64(data[112:], ctx.Arg0)
	ByteOrder.PutUint64(data[104:], ctx.Arg1)
	ByteOrder.PutUint64(data[96:], ctx.Arg2)
	ByteOrder.PutUint64(data[88:], ctx.Arg3)
	ByteOrder.PutUint64(data[72:], ctx.Arg4)

	return data
}
