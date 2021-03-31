workspace(name = "s2a_core")

local_repository(
    name = "s2a_core",
    path = "..",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Abseil
http_archive(
  name = "com_google_absl",
strip_prefix = "abseil-cpp-64461421222f8be8663c50e8e82c91c3f95a0d3c",
            url = "https://github.com/abseil/abseil-cpp/archive/64461421222f8be8663c50e8e82c91c3f95a0d3c.zip",
            sha256 = "41d725950d0d3ed4d00020881db84fdc79ac349d9b325ab010686c5a794a822e",
)

# Googletest
http_archive(
    name = "com_google_googletest",
    sha256 = "ff7a82736e158c077e76188232eac77913a15dac0b22508c390ab3f88e6d6d86",
    strip_prefix = "googletest-b6cd405286ed8635ece71c72f118e659f4ade3fb",
    urls = ["https://github.com/google/googletest/archive/b6cd405286ed8635ece71c72f118e659f4ade3fb.zip"]
)

# UPB
http_archive(
    name = "upb",
    sha256 = "487d84ce85065ff89ccde1c1ac2ea1515d2be411306e4adf1be6861dc4a4a86b",
    strip_prefix = "upb-de76b31f9c56b28120580d53a6f8d7941fdb79eb",
    urls = [
      "https://github.com/protocolbuffers/upb/archive/de76b31f9c56b28120580d53a6f8d7941fdb79eb.tar.gz",
    ],
)

load("@upb//bazel:workspace_deps.bzl", "upb_deps")
upb_deps()

# BoringSSL
http_archive(
    name = "boringssl",
    strip_prefix = "boringssl-597b810379e126ae05d32c1d94b1a9464385acd0",
    url = "https://github.com/google/boringssl/archive/597b810379e126ae05d32c1d94b1a9464385acd0.zip",
    sha256 = "c4e8414cb36e62d2fee451296cc864f7ad1a4670396c8a67e1ee77ae84cc4167",
)

# Rules foreign, needed to convert OpenSSL CMake to Bazel.
http_archive(
    name = "rules_foreign_cc",
    strip_prefix = "rules_foreign_cc-master",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/master.zip",
)

load("@rules_foreign_cc//:workspace_definitions.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

_ALL_CONTENT = """filegroup(name = "all", srcs = glob(["**"]), visibility = ["//visibility:public"])"""

# OpenSSL
http_archive(
    name = "openssl",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "openssl-OpenSSL_1_1_1f",
    urls = ["https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz"]
)

