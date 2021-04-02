# Copyright 2021 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script generates the .upb.{h,c} files used by the S2A Core for the CMake
# build. It should be called from the top-level directory only. Don't forget to
# ensure this file is executable.

set -ex

if [ $# -eq 0 ]; then
  UPB_OUTPUT_DIR=$PWD/proto/upb-generated
  rm -rf $UPB_OUTPUT_DIR
  mkdir -p $UPB_OUTPUT_DIR
else
  UPB_OUTPUT_DIR=$1/upb-generated
  mkdir $UPB_OUTPUT_DIR
  mkdir $UPBDEFS_OUTPUT_DIR
fi

bazel build @com_google_protobuf//:protoc
PROTOC=$PWD/bazel-bin/external/com_google_protobuf/protoc

bazel build @upb//upbc:protoc-gen-upb
UPB_PLUGIN=$PWD/bazel-bin/external/upb/upbc/protoc-gen-upb

proto_files=( \
  "proto/common.proto" \
  "proto/s2a.proto" \
  "proto/s2a_context.proto")

for i in "${proto_files[@]}"
do
  echo "Compiling: ${i}"
  $PROTOC \
    $i \
    --upb_out=$UPB_OUTPUT_DIR \
    --plugin=protoc-gen-upb=$UPB_PLUGIN
done
