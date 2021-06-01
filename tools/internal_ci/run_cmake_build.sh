#!/bin/bash

# Copyright 2021 Google LLC
#
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

# Fail on any error.
set -e

# Display commands being run.
set -x

readonly PLATFORM="$(uname | tr '[:upper:]' '[:lower:]')"

git submodule update --init --recursive

case "${PLATFORM}" in
  'linux')
    # If we ever need to switch to use OpenSSL for the GCP Ubuntu Kokoro tests,
    # then we need to upgrade the OpenSSL version, because they come with 1.0.2g
    # by default (which does have not the ChaChaPoly cipher).

    openssl version
    openssl version -a
    #sudo apt-get update
    #sudo apt-get upgrade openssl

    wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz
    tar -zxf openssl-1.1.1g.tar.gz && cd openssl-1.1.1g
    ./config
    make
    sudo mv /usr/bin/openssl ~/tmp
    sudo make install
    sudo ln -s /usr/local/bin/openssl /usr/bin/openssl
    sudo ldconfig

    openssl version
    openssl version -a

    echo "================================= Running cmake"
    cmake --version
    # The -Wno-unused-result flag is needed because of BoringSSL.
    cmake . -DS2A_CORE_FIND_OPENSSL="true" -DDEFINE_S2A_CORE_USE_NEW_UPB_APIS=1 -DCMAKE_CXX_STANDARD=11 -DCMAKE_CXX_FLAGS="-Wno-unused-result"
  ;;
  'darwin')
    brew install openssl
    brew link openssl --force
    echo "================================= Running cmake"
    cmake --version
    cmake . -DDEFINE_S2A_CORE_USE_NEW_UPB_APIS=1 -DS2A_CORE_FIND_OPENSSL="true" -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib -DCMAKE_CXX_STANDARD=11
  ;;
  *)
    echo "Unsupported platform, unable to run cmake."
    exit 1
  ;;
esac

echo "================================= Building with make"
make all
