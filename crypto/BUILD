#Copyright 2020 Google LLC

#Licensed under the Apache License, Version 2.0(the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#https:  // www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

#Description:
#This BUILD file contains the libraries and tests for the AEAD crypter used by the S2A client \
    libraries.

load("@rules_foreign_cc//tools/build_defs:configure.bzl", "configure_make")

    licenses(["notice"])

        default_visibility =
            [
              "//record_protocol:__pkg__",
            ]

    package(default_visibility = default_visibility)

        cc_library(name = "hkdf",
                   srcs =
                       [
                         "hkdf.cc",
                       ],
                   hdrs = ["hkdf.h"],
                   deps =
                       [
                         "@boringssl//:crypto",
                         "@com_google_absl//absl/status",
                       ], )

            cc_library(name = "s2a_aead_crypter",
                       srcs =
                           [
                             "aes_gcm_crypter.cc",
                             "chacha_poly_crypter_boringssl.cc",
                             "chacha_poly_crypter_openssl.cc",
                             "s2a_aead_crypter.cc",
                           ],
                       hdrs =
                           [
                             "s2a_aead_constants.h",
                             "s2a_aead_crypter.h",
                           ],
                       deps =
                           [
                             ":s2a_aead_crypter_util",
                             "@boringssl//:crypto",
                             "@com_google_absl//absl/memory",
                             "@com_google_absl//absl/status",
                             "@com_google_absl//absl/strings",
                             "@com_google_absl//absl/types:variant",
                           ], )

                cc_library(name = "s2a_aead_crypter_util",
                           srcs =
                               [
                                 "s2a_aead_crypter_util.cc",
                               ],
                           hdrs = ["s2a_aead_crypter_util.h"],
                           deps =
                               [
                                 "@boringssl//:crypto",
                               ], )

                    cc_library(name = "s2a_aead_crypter_test_util",
                               srcs = ["s2a_aead_crypter_test_util.cc"],
                               hdrs = ["s2a_aead_crypter_test_util.h"],
                               deps =
                                   [
                                     ":s2a_aead_crypter",
                                     "@com_google_absl//absl/base:core_headers",
                                   ], )

                        cc_test(name = "hkdf_test", srcs = ["hkdf_test.cc"],
                                deps =
                                    [
                                      ":hkdf",
                                      "//test_util:s2a_test_util",
                                      "@com_google_googletest//:gtest_main",
                                    ], )

                            cc_test(name = "s2a_aead_crypter_test",
                                    srcs = ["s2a_aead_crypter_test.cc"],
                                    deps =
                                        [
                                          ":s2a_aead_crypter",
                                          "@com_google_absl//absl/status",
                                          "@com_google_googletest//:gtest_main",
                                        ], )

                                cc_test(name = "aes_gcm_crypter_test",
                                        srcs = ["aes_gcm_crypter_test.cc"],
                                        deps =
                                            [
                                              ":s2a_aead_crypter",
                                              ":s2a_aead_crypter_test_util",
                                              "//test_util:s2a_test_util",
                                              "@com_google_absl//absl/status",
                                              "@com_google_googletest//:gtest_main",
                                            ], )

                                    cc_test(name = "chacha_poly_crypter_test",
                                            srcs = ["chacha_poly_crypter_test.cc"],
                                            deps =
                                                [
                                                  ":s2a_aead_crypter",
                                                  ":s2a_aead_crypter_test_util",
                                                  "//test_util:s2a_test_util",
                                                  "@com_google_absl//absl/status",
                                                  "@com_google_googletest//:gtest_main",
                                                ], )

                                        cc_test(name = "s2a_aead_crypter_util_test",
                                                srcs =
                                                    [
                                                      "s2a_aead_crypter_util_test.cc",
                                                    ],
                                                deps =
                                                    [
                                                      ":s2a_aead_crypter_util",
                                                      "@boringssl//:crypto",
                                                      "@boringssl//:ssl",
                                                      "@com_google_googletest//:gtest_main",
                                                    ], )

#OpenSSL - specific libraries and tests.

                                            config_setting(name = "darwin_build",
                                                           values = {"cpu" : "darwin"}, )

                                                configure_make(name = "openssl",
                                                               configure_command = "config",
                                                               configure_options = select({
                                                                 ":darwin_build" : [
                                                                   "shared", "ARFLAGS=r",
                                                                   "enable-ec_nistp_64_gcc_128",
                                                                   "no-ssl2", "no-ssl3", "no-comp"
                                                                 ],
                                                                 "//conditions:default" : []
                                                               }),
                                                               lib_source = "@openssl//:all",
                                                               configure_env_vars = select({
                                                                 ":darwin_build" : {
                                                                   "OSX_DEPLOYMENT_TARGET" :
                                                                       "10.14",
                                                                   "AR" : "",
                                                                 },
                                                                 "//conditions:default" : {}
                                                               }),
                                                               shared_libraries = select({
                                                                 ":darwin_build" : [
                                                                   "libssl.dylib",
                                                                   "libcrypto.dylib",
                                                                 ],
                                                                 "//conditions:default" : [
                                                                   "libssl.so",
                                                                   "libcrypto.so",
                                                                 ],
                                                               }))

                                                    cc_library(
                                                        name = "chacha_poly_crypter_openssl",
                                                        testonly = 1,
                                                        srcs =
                                                            [
                                                              "chacha_poly_crypter_openssl.cc",
                                                              "s2a_aead_crypter.cc",
                                                            ],
                                                        hdrs =
                                                            [
                                                              "s2a_aead_constants.h",
                                                              "s2a_aead_crypter.h",
                                                            ],
                                                        deps =
                                                            [
                                                              ":openssl",
                                                              "@com_google_absl//absl/memory",
                                                              "@com_google_absl//absl/status",
                                                              "@com_google_absl//absl/strings",
                                                              "@com_google_absl//absl/"
                                                              "types:variant",
                                                            ], )

                                                        cc_test(
                                                            name =
                                                                "chacha_poly_crypter_openssl_test",
                                                            srcs = ["chacha_poly_crypter_test.cc"],
                                                            deps = [
                                                              ":chacha_poly_crypter_openssl",
                                                              ":s2a_aead_crypter_test_util",
                                                              "//test_util:s2a_test_util",
                                                              "@com_google_googletest//:gtest_main",
                                                            ], )
