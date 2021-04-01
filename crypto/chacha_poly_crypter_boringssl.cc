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

#ifdef OPENSSL_IS_BORINGSSL

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/aead.hi>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "crypto/s2a_aead_crypter.h"
#include "crypto/s2a_aead_crypter_util.h"

namespace s2a {
namespace aead_crypter {

using ::absl::Status;
using ::absl::StatusCode;

// |ChachaPolyS2AAeadCrypterBoringSSL| implements the |S2AAeadCrypter| interface
// using BoringSSL's AEAD methods.
//
// This class is not thread-safe.
class ChachaPolyS2AAeadCrypterBoringSSL : public S2AAeadCrypter {
 public:
  ChachaPolyS2AAeadCrypterBoringSSL(bssl::UniquePtr<EVP_AEAD_CTX> ctx,
                                    size_t key_length, size_t nonce_length,
                                    size_t tag_length)
      : S2AAeadCrypter(key_length, nonce_length, tag_length),
        ctx_(std::move(ctx)) {}

  ~ChachaPolyS2AAeadCrypterBoringSSL() override {}

  CrypterStatus Encrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& plaintext,
                        Iovec ciphertext_and_tag) override {
    // Input checks.
    ABSL_ASSERT(ciphertext_and_tag.iov_base != nullptr);

    if (nonce.size() != NonceLength()) {
      return CrypterStatus(
          Status(StatusCode::kInvalidArgument, "|nonce| has invalid length."),
          /*bytes_written=*/0);
    }
    size_t max_out_len = ciphertext_and_tag.iov_len;
    size_t in_len = 0;
    for (auto& vec : plaintext) {
      if (vec.iov_len != 0 && vec.iov_base == nullptr) {
        return CrypterStatus(
            Status(StatusCode::kInvalidArgument,
                   "non-zero plaintext length but plaintext is nullptr."),
            /*bytes_written=*/0);
      }
      if (vec.iov_len == 0) {
        continue;
      }
      in_len += vec.iov_len;
    }

    // Check that |max_out_len| is big enough to hold tag before proceeding.
    if (max_out_len < TagLength() + in_len) {
      return CrypterStatus(Status(StatusCode::kInvalidArgument,
                                  "|ciphertext_and_tag| is too small to "
                                  "hold the resulting ciphertext and tag."),
                           /*bytes_written=*/0);
    }

    // Collect the plaintext into the single |in_vec| vector.
    std::vector<uint8_t> in_vec;
    for (auto& vec : plaintext) {
      if (vec.iov_len == 0) {
        continue;
      }
      uint8_t* tmp = static_cast<uint8_t*>(vec.iov_base);
      in_vec.insert(in_vec.end(), tmp, tmp + vec.iov_len);
    }

    // Collect the aad vec into the single |aad_vec| vector.
    std::vector<uint8_t> aad_vec;
    size_t aad_vec_len = 0;
    for (auto& vec : aad) {
      if (vec.iov_len != 0 && vec.iov_base == nullptr) {
        return CrypterStatus(
            Status(StatusCode::kInvalidArgument,
                   "non-zero aad length but |aad| is nullptr."),
            /*bytes_written=*/0);
      }
      if (vec.iov_len == 0) {
        continue;
      }
      aad_vec_len += vec.iov_len;
      uint8_t* tmp = static_cast<uint8_t*>(vec.iov_base);
      aad_vec.insert(aad_vec.end(), tmp, tmp + vec.iov_len);
    }

    // To keep UBSAN happy.
    uint8_t* in =
        in_vec.empty() ? nullptr : const_cast<uint8_t*>(in_vec.data());
    uint8_t* ad =
        aad_vec.empty() ? nullptr : const_cast<uint8_t*>(aad_vec.data());

    // |out_len| is set to the actual bytes written by |EVP_AEAD_CTX_seal|.
    size_t out_len = 0;
    uint8_t* out = static_cast<uint8_t*>(ciphertext_and_tag.iov_base);
    if (EVP_AEAD_CTX_seal(ctx_.get(), out, &out_len, max_out_len,
                          const_cast<uint8_t*>(nonce.data()), nonce.size(), in,
                          in_vec.size(), ad, aad_vec.size()) != 1) {
      return CrypterStatus(
          Status(StatusCode::kInternal,
                 absl::StrCat("seal operation failed. ", GetSSLErrors())),
          /*bytes_written=*/0);
    }
    out += out_len;
    max_out_len -= out_len;
    size_t bytes_written = ciphertext_and_tag.iov_len - max_out_len;

    return CrypterStatus(Status(), bytes_written);
  }

  CrypterStatus Decrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& ciphertext_and_tag,
                        Iovec plaintext) override {
    // Input checks.
    if (plaintext.iov_len != 0) {
      ABSL_ASSERT(plaintext.iov_base != nullptr);
    }

    if (nonce.size() != NonceLength()) {
      return CrypterStatus(
          Status(StatusCode::kInvalidArgument, "|nonce| has invalid length."),
          0);
    }
    size_t max_out_len = plaintext.iov_len;
    size_t in_len = 0;
    for (auto& vec : ciphertext_and_tag) {
      if (vec.iov_len != 0 && vec.iov_base == nullptr) {
        return CrypterStatus(
            Status(StatusCode::kInvalidArgument,
                   "non-zero ciphertext length but ciphertext is nullptr."),
            /*bytes_written=*/0);
      }
      if (vec.iov_len == 0) {
        continue;
      }
      in_len += vec.iov_len;
    }

    // Check that the total ciphertext length is big enough to hold a tag.
    if (in_len < kChachaPolyTagSize) {
      return CrypterStatus(
          Status(StatusCode::kInvalidArgument,
                 "|ciphertext_and_tag| is too small to hold a tag."),
          /*bytes_written=*/0);
    }

    // Check that |max_out_len| is big enough to hold tag before proceeding.
    if (max_out_len < in_len - kChachaPolyTagSize) {
      return CrypterStatus(
          Status(StatusCode::kInvalidArgument,
                 "|plaintext| is too small to hold the resulting plaintext."),
          /*bytes_written=*/0);
    }

    // Collect the ciphertext and tag into the single |in_vec| vector.
    std::vector<uint8_t> in_vec;
    for (auto& vec : ciphertext_and_tag) {
      if (vec.iov_len == 0) {
        continue;
      }
      uint8_t* tmp = static_cast<uint8_t*>(vec.iov_base);
      in_vec.insert(in_vec.end(), tmp, tmp + vec.iov_len);
    }

    // Collect the aad vec into the single |aad_vec| vector.
    std::vector<uint8_t> aad_vec;
    size_t aad_vec_len = 0;
    for (auto& vec : aad) {
      if (vec.iov_len != 0 && vec.iov_base == nullptr) {
        return CrypterStatus(
            Status(StatusCode::kInvalidArgument,
                   "non-zero aad length but |aad| is nullptr."),
            /*bytes_written=*/0);
      }
      if (vec.iov_len == 0) {
        continue;
      }
      aad_vec_len += vec.iov_len;
      uint8_t* tmp = static_cast<uint8_t*>(vec.iov_base);
      aad_vec.insert(aad_vec.end(), tmp, tmp + vec.iov_len);
    }

    // To keep UBSAN happy.
    uint8_t* in =
        in_vec.empty() ? nullptr : const_cast<uint8_t*>(in_vec.data());
    uint8_t* ad =
        aad_vec.empty() ? nullptr : const_cast<uint8_t*>(aad_vec.data());

    // |out_len| is set to the actual bytes written by |EVP_AEAD_CTX_open|.
    size_t out_len = 0;
    uint8_t* out = static_cast<uint8_t*>(plaintext.iov_base);
    if (EVP_AEAD_CTX_open(ctx_.get(), out, &out_len, max_out_len,
                          const_cast<uint8_t*>(nonce.data()), nonce.size(), in,
                          in_vec.size(), ad, aad_vec.size()) != 1) {
      return CrypterStatus(
          Status(StatusCode::kInternal,
                 absl::StrCat("open operation failed. ", GetSSLErrors())),
          /*bytes_written=*/0);
    }
    out += out_len;
    max_out_len -= out_len;
    size_t bytes_written = plaintext.iov_len - max_out_len;

    return CrypterStatus(Status(), bytes_written);
  }

 private:
  bssl::UniquePtr<EVP_AEAD_CTX> ctx_;
};

absl::variant<Status, std::unique_ptr<S2AAeadCrypter>>
CreateChachaPolyAeadCrypter(const std::vector<uint8_t>& key) {
  // Check key length.
  if (key.size() != kChachaPolyKeySize) {
    return Status(StatusCode::kInvalidArgument, "Key size is unsupported.");
  }

  // Create and initialize the cipher context.
  bssl::UniquePtr<EVP_AEAD_CTX> ctx(
      EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(),
                       reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                       kChachaPolyTagSize));
  if (!ctx) {
    return Status(StatusCode::kInternal,
                  absl::StrCat("Initialization of |EVP_AEAD_CTX| failed: ",
                               GetSSLErrors()));
  }
  return absl::make_unique<ChachaPolyS2AAeadCrypterBoringSSL>(
      std::move(ctx), kChachaPolyKeySize, kChachaPolyNonceSize,
      kChachaPolyTagSize);
}

}  // namespace aead_crypter
}  // namespace s2a

#endif
