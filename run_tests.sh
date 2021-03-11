#!/bin/bash

# Fail on any error.
set -e

# Display commands being run.
set -x

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

fail_with_debug_output() {
  ls -l
  df -h /
  exit 1
}

run_tests() {
  local -a TEST_FLAGS=( --strategy=TestRunner=standalone --test_output=all )
  readonly TEST_FLAGS
  (
    time bazel build --features=-debug_prefix_map_pwd_is_dot -- ... || fail_with_debug_output
    time bazel test --features=-debug_prefix_map_pwd_is_dot "${TEST_FLAGS[@]}" -- ... || fail_with_debug_output
  )
}

install_protoc() {
  local protoc_version='3.14.0'
  local protoc_platform
  case "${PLATFORM}" in
    'linux')
      protoc_platform='linux-x86_64'
      ;;
    'darwin')
      protoc_platform='osx-x86_64'
      ;;
    *)
      echo "Unsupported platform, unable to install protoc."
      exit 1
      ;;
  esac
  local protoc_zip="protoc-${protoc_version}-${protoc_platform}.zip"
  local protoc_url="https://github.com/protocolbuffers/protobuf/releases/download/v${protoc_version}/${protoc_zip}"
  local -r protoc_tmpdir=$(mktemp -dt tink-protoc.XXXXXX)
  (
    cd "${protoc_tmpdir}"
    curl -OL "${protoc_url}"
    unzip ${protoc_zip} bin/protoc
  )
  export PATH="${protoc_tmpdir}/bin:${PATH}"
}

main() {
  if [[ -n "${KOKORO_ROOT}" ]]; then
    use_bazel.sh latest
    install_protoc
  fi

  echo "using bazel binary: $(which bazel)"
  bazel version

  echo "using protoc: $(which protoc)"
  protoc --version

  run_tests
}

main "$@"
