#!/bin/bash

# Fail on any error.
set -e

cd "${KOKORO_ARTIFACTS_DIR}/github/s2a-core"
./tools/internal_ci/run_cmake_build.sh
