// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sign

import (
	"strings"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
)

var data = []byte("qwerty")

func Test_PlainData(t *testing.T) {
	pd := PlainData{Data: data}

	pae := pd.PreAuthEncoding()
	assert.Equal(t, pae, data)

	bundle := &protobundle.Bundle{}
	pd.Bundle(bundle, data, data, protocommon.HashAlgorithm_SHA2_256)
	assert.NotNil(t, bundle.GetMessageSignature())
	assert.Nil(t, bundle.GetDsseEnvelope())
}

func Test_DSSEData(t *testing.T) {
	dsseData := DSSEData{Data: data, PayloadType: "something"}

	pae := dsseData.PreAuthEncoding()
	assert.True(t, strings.HasPrefix(string(pae), "DSSE"))

	bundle := &protobundle.Bundle{}
	dsseData.Bundle(bundle, data, data, protocommon.HashAlgorithm_SHA2_256)
	assert.Nil(t, bundle.GetMessageSignature())
	assert.NotNil(t, bundle.GetDsseEnvelope())
}
