/*
 *
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "crypto/s2a_aead_crypter_util.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace s2a {
namespace aead_crypter {
namespace {

TEST(GetSSLErrorsTest, SSLErrorEmpty) {
  const std::string error = GetSSLErrors();
  EXPECT_TRUE(error.empty()) << error;
}

TEST(GetSSLErrorsTest, SSLErrorNotEmpty) {
  ERR_put_error(ERR_LIB_SSL, 0, SSL_R_SSL_HANDSHAKE_FAILURE, __FILE__,
                __LINE__);

  std::string error = GetSSLErrors();
  EXPECT_TRUE(!error.empty());

  // |GetSSLErrors| clears the SSL error queue. Thus, the second call to
  // |GetSSLErrors| should return an empty error string.
  error = GetSSLErrors();
  EXPECT_TRUE(error.empty()) << error;
}

}  // namespace
}  // namespace aead_crypter
}  // namespace s2a
