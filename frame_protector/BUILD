# Copyright 2020 Google LLC

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

# Description:
#   This BUILD file contains targets for the S2A client's frame protector.

load("//:acl.bzl", "approved_s2a_core_users")

licenses(["notice"])

cc_library(
    name = "s2a_frame_protector",
    srcs = [
        "s2a_frame_protector.cc",
    ],
    hdrs = [
        "s2a_frame_protector.h",
    ],
    visibility = approved_s2a_core_users,
    deps = [
        "//:s2a_constants",
        "//channel:s2a_channel",
        "//options:s2a_options",
        "//record_protocol:s2a_crypter",
        "//record_protocol:s2a_ticket_sender",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
    ],
)

cc_test(
    name = "s2a_frame_protector_test",
    srcs = ["s2a_frame_protector_test.cc"],
    external_deps = [
        "libssl",
    ],
    deps = [
        ":s2a_frame_protector",
        "//:s2a_constants",
        "//record_protocol:s2a_crypter",
        "//test_util:s2a_test_data",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)
