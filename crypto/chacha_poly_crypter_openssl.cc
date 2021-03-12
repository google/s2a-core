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

#include <openssl/base.h>

#ifndef OPENSSL_IS_BORINGSSL

#include "crypto/s2a_aead_crypter.h"

namespace s2a {
namespace aead_crypter {

using ::absl::Status;
using ::absl::StatusCode;

// |ChachaPolyS2AAeadCrypterOpenSSL| implements the |S2AAeadCrypter| interface
// using the OpenSSL library.
//
// This class is not thread-safe.
class ChachaPolyS2AAeadCrypterOpenSSL : public S2AAeadCrypter {
 public:
  ChachaPolyS2AAeadCrypterOpenSSL(const std::vector<uint8_t>& key,
                                  size_t nonce_length, size_t tag_length)
      : S2AAeadCrypter(key.size(), nonce_length, tag_length) {
    // This line should be unreachable because |ChachaPolyS2AAeadCrypterOpenSSL|
    // is unimplemented.
    ABSL_ASSERT(0);
  }

  ~ChachaPolyS2AAeadCrypterOpenSSL() override {}

  CrypterStatus Encrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& plaintext,
                        Iovec ciphertext_and_tag) override {
    return CrypterStatus(Status(StatusCode::kUnimplemented,
                                "OpenSSL library is not yet supported."),
                         /*bytes_written=*/0);
  }

  CrypterStatus Decrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& ciphertext_and_tag,
                        Iovec plaintext) override {
    return CrypterStatus(Status(StatusCode::kUnimplemented,
                                "OpenSSL library is not yet supported."),
                         /*bytes_written=*/0);
  }
};

absl::variant<Status, std::unique_ptr<S2AAeadCrypter>>
CreateChachaPolyAeadCrypter(const std::vector<uint8_t>& key) {
  return Status(StatusCode::kUnimplemented,
                "OpenSSL library is not yet support. BoringSSL required.");
}

}  // namespace aead_crypter
}  // namespace s2a

#endif
