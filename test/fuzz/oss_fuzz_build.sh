#!/bin/bash -eu
# Copyright 2024 The Sigstore Authors.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/bundle FuzzBundle FuzzBundle
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/tlog FuzzParseEntry FuzzParseEntry
mkdir pkg/verify/fuzz && mv pkg/verify/fuzz_test.go pkg/verify/fuzz/
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifyTimestampAuthorityWithoutThreshold FuzzVerifyTimestampAuthorityWithoutThreshold
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifyTimestampAuthorityWithThreshold FuzzVerifyTimestampAuthorityWithThreshold
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifyArtifactTransparencyLog FuzzVerifyArtifactTransparencyLog
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifier FuzzVerifier
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifySignatureWithoutArtifactOrDigest FuzzVerifySignatureWithoutArtifactOrDigest
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifySignatureWithArtifactWithoutDigest FuzzVerifySignatureWithArtifactWithoutDigest
compile_native_go_fuzzer github.com/sigstore/sigstore-go/pkg/verify/fuzz FuzzVerifySignatureWithArtifactDigest FuzzVerifySignatureWithArtifactDigest

zip -j $OUT/FuzzVerifier_seed_corpus.zip examples/trusted-root-public-good.json

for fuzzer in FuzzVerifyTimestampAuthorityWithoutThreshold FuzzVerifyTimestampAuthorityWithThreshold FuzzVerifyArtifactTransparencyLog FuzzVerifySignatureWithoutArtifactOrDigest FuzzVerifySignatureWithArtifactWithoutDigest FuzzVerifySignatureWithArtifactDigest; do
  cp test/fuzz/dictionaries/intoto_json.dict $OUT/$fuzzer.dict
  zip -j $OUT/"$fuzzer"_seed_corpus.zip examples/sigstore-go-signing/intoto.txt
done 
