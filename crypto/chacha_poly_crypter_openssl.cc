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

#ifndef OPENSSL_IS_BORINGSSL

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "crypto/s2a_aead_crypter.h"

namespace s2a {
namespace aead_crypter {
namespace {

// TODO(matthewstevenson88) Use s2a_aead_crypter_util.{h,cc} instead.
std::string GetSSLErrors() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* temp_buffer = nullptr;
  size_t temp_buffer_length = BIO_get_mem_data(bio, &temp_buffer);
  std::string error_message(temp_buffer, temp_buffer_length);
  BIO_free_all(bio);
  return error_message;
}

// Initialize |ctx| for encryption using |nonce|. The caller must not pass in
// nullptr for |ctx|.
absl::Status EncryptInitContextUsingNonce(EVP_CIPHER_CTX* ctx,
                                          const std::vector<uint8_t>& nonce) {
  ABSL_ASSERT(ctx != nullptr);
  if (nonce.size() != kChachaPolyNonceSize) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "|nonce| has invalid length.");
  }
  if (!EVP_EncryptInit_ex(ctx, /*cipher=*/nullptr, /*impl=*/nullptr,
                          /*key=*/nullptr, nonce.data())) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Initializing Chacha-Poly nonce failed. " + GetSSLErrors());
  }
  return absl::Status();
}

// Initialize |ctx| for decryption using |nonce|. The caller must not pass in
// nullptr for |ctx|.
absl::Status DecryptInitContextUsingNonce(EVP_CIPHER_CTX* ctx,
                                          const std::vector<uint8_t>& nonce) {
  ABSL_ASSERT(ctx != nullptr);
  if (nonce.size() != kChachaPolyNonceSize) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "|nonce| has invalid length.");
  }
  if (!EVP_DecryptInit_ex(ctx, /*cipher=*/nullptr, /*impl=*/nullptr,
                          /*key=*/nullptr, nonce.data())) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Initializing ChachaPoly nonce failed. " + GetSSLErrors());
  }
  return absl::Status();
}

// Checks the authentication tag in |tag| against |ctx|, ensures that the
// correct number of bytes were written to |plaintext|, and finalizes the
// decryption. The caller must not pass in nullptr for |ctx|.
absl::Status DecryptCheckTagAndFinalize(EVP_CIPHER_CTX* ctx, Iovec tag,
                                        Iovec plaintext) {
  ABSL_ASSERT(ctx != nullptr);
  ABSL_ASSERT(tag.iov_len == kChachaPolyTagSize);
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kAesGcmTagSize,
                           tag.iov_base)) {
    memset(plaintext.iov_base, 0x00, plaintext.iov_len);
    return absl::Status(absl::StatusCode::kInternal,
                        "Setting tag failed. " + GetSSLErrors());
  }
  int bytes_written_temp = 0;
  if (!EVP_DecryptFinal_ex(ctx, /*outm=*/nullptr, &bytes_written_temp)) {
    memset(plaintext.iov_base, 0x00, plaintext.iov_len);
    return absl::Status(absl::StatusCode::kInternal,
                        "Checking tag failed: " + GetSSLErrors());
  }
  if (bytes_written_temp != 0) {
    memset(plaintext.iov_base, 0x00, plaintext.iov_len);
    return absl::Status(
        absl::StatusCode::kInternal,
        "SSL library wrote some unexpected bytes. " + GetSSLErrors());
  }
  return absl::Status();
}

// Sets the authentication data of |ctx| using |aad|. The caller must not pass
// in nullptr for |ctx|.
absl::Status SetAadForEncrypt(EVP_CIPHER_CTX* ctx, const std::vector<Iovec>& aad) {
  ABSL_ASSERT(ctx != nullptr);
  for (auto& vec : aad) {
    // If |vec| has no content, proceed to the next |Iovec|. If the length of
    // |vec| is nonzero, then |vec.iov_base| must not be nullptr.
    if (vec.iov_len == 0) {
      continue;
    }
    if (vec.iov_base == nullptr) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "non-zero aad length but aad is nullptr.");
    }

    size_t aad_bytes_read = 0;
    if (!EVP_EncryptUpdate(ctx, /*out=*/nullptr,
                           reinterpret_cast<int*>(&aad_bytes_read),
                           static_cast<uint8_t*>(vec.iov_base),
                           static_cast<int>(vec.iov_len)) ||
        aad_bytes_read != vec.iov_len) {
      return absl::Status(
          absl::StatusCode::kInternal,
          "Setting authenticated associated data failed. " + GetSSLErrors());
    }
  }
  return absl::Status();
}

// Sets the authentication data of |ctx| using |aad|. The caller must not pass
// in nullptr for |ctx|.
absl::Status SetAadForDecrypt(EVP_CIPHER_CTX* ctx, const std::vector<Iovec>& aad) {
  ABSL_ASSERT(ctx != nullptr);
  for (auto& vec : aad) {
    // If |vec| has no content, proceed to the next |Iovec|. If the length of
    // |vec| is nonzero, then |vec.iov_base| must not be nullptr.
    if (vec.iov_len == 0) {
      continue;
    }
    if (vec.iov_base == nullptr) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "non-zero aad length but aad is nullptr.");
    }

    size_t aad_bytes_read = 0;
    if (!EVP_DecryptUpdate(ctx, /*out=*/nullptr,
                           reinterpret_cast<int*>(&aad_bytes_read),
                           static_cast<uint8_t*>(vec.iov_base),
                           static_cast<int>(vec.iov_len)) ||
        aad_bytes_read != vec.iov_len) {
      return absl::Status(
          absl::StatusCode::kInternal,
          "Setting authenticated associated data failed. " + GetSSLErrors());
    }
  }
  return absl::Status();
}

}  // namespace

// |ChachaPolyS2AAeadCrypterOpenSSL| implements the |S2AAeadCrypter| interface
// using the OpenSSL library.
//
// This class is not thread-safe.
class ChachaPolyS2AAeadCrypterOpenSSL : public S2AAeadCrypter {
 public:
  ChachaPolyS2AAeadCrypterOpenSSL(
      std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> ctx,
      const std::vector<uint8_t>& key, size_t nonce_length, size_t tag_length)
      : S2AAeadCrypter(key.size(), nonce_length, tag_length),
        ctx_(std::move(ctx)) {}

  ~ChachaPolyS2AAeadCrypterOpenSSL() override {}

  CrypterStatus Encrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& plaintext,
                        Iovec ciphertext_and_tag) override {
    // Input checks.
    ABSL_ASSERT(ciphertext_and_tag.iov_base != nullptr);

    // Init Openssl context using |nonce|.
    absl::Status nonce_status = EncryptInitContextUsingNonce(ctx_.get(), nonce);
    if (!nonce_status.ok()) {
      return CrypterStatus(nonce_status, /*bytes_written=*/0);
    }

    // Set the authentication data using |aad|.
    absl::Status aad_status = SetAadForEncrypt(ctx_.get(), aad);
    if (!aad_status.ok()) {
      return CrypterStatus(aad_status, /*bytes_written=*/0);
    }

    uint8_t* ciphertext_ptr =
        static_cast<uint8_t*>(ciphertext_and_tag.iov_base);
    size_t remaining_ciphertext_length = ciphertext_and_tag.iov_len;

    // Encrypt |plaintext|.
    for (const auto& vec : plaintext) {
      // If |vec| has no content, proceed to the next |Iovec|. If the length of
      // |vec| is nonzero, then |vec.iov_base| must not be nullptr.
      if (vec.iov_len == 0) continue;
      if (vec.iov_base == nullptr) {
        return CrypterStatus(
            absl::InvalidArgumentError("|plaintext| has an invalid component."),
            /*bytes_written=*/0);
      }

      // Check that there is sufficient space remaining in |ciphertext_and_tag|.
      // If there is, write the ciphertext to |ciphertext_ptr|.
      if (remaining_ciphertext_length < vec.iov_len) {
        return CrypterStatus(absl::InvalidArgumentError(absl::StrCat(
                                 "|ciphertext_and_tag| is not large enough to "
                                 "hold the result of encrypting |plaintext|. ",
                                 GetSSLErrors())),
                             /*bytes_written=*/0);
      }
      int bytes_written = 0;
      if (!EVP_EncryptUpdate(ctx_.get(), ciphertext_ptr, &bytes_written,
                             static_cast<uint8_t*>(vec.iov_base),
                             static_cast<int>(vec.iov_len))) {
        return CrypterStatus(
            absl::InternalError(absl::StrCat("Encrypting |plaintext| failed. " +
                                             GetSSLErrors())),
            /*bytes_written=*/0);
      }
      if (bytes_written > static_cast<int>(vec.iov_len)) {
        return CrypterStatus(
            absl::InternalError(absl::StrCat(
                "More bytes written than expected. ", GetSSLErrors())),
            /*bytes_written=*/0);
      }
      ciphertext_ptr += bytes_written;
      remaining_ciphertext_length -= bytes_written;
    }

    // Finalize encryption and ensure that the SSL library did not write any
    // extra bytes.
    int extra_bytes_written = 0;
    if (!EVP_EncryptFinal_ex(ctx_.get(), /*out=*/nullptr,
                             &extra_bytes_written)) {
      return CrypterStatus(
          absl::InternalError(
              absl::StrCat("Finalizing encryption failed. ", GetSSLErrors())),
          /*bytes_written=*/0);
    }
    if (extra_bytes_written != 0) {
      return CrypterStatus(absl::InternalError(absl::StrCat(
                               "Wrote unexpected bytes. ", GetSSLErrors())),
                           /*bytes_written=*/0);
    }

    // Ensure that |ciphertext_ang_tag| has enough space remaining to write the
    // authentication tag. If so, write the tag.
    if (remaining_ciphertext_length < kChachaPolyTagSize) {
      return CrypterStatus(
          absl::InvalidArgumentError(
              "|ciphertext_and_tag| is too small to hold the resulting ciphertext and tag."),
          /*bytes_written=*/0);
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG,
                             kChachaPolyTagSize, ciphertext_ptr)) {
      return CrypterStatus(absl::InternalError(absl::StrCat(
                               "Writing tag failed. ", GetSSLErrors())),
                           /*bytes_written=*/0);
    }
    ciphertext_ptr += kChachaPolyTagSize;
    remaining_ciphertext_length -= kChachaPolyTagSize;

    return CrypterStatus(absl::OkStatus(), ciphertext_and_tag.iov_len -
                                               remaining_ciphertext_length);
  }

  CrypterStatus Decrypt(const std::vector<uint8_t>& nonce,
                        const std::vector<Iovec>& aad,
                        const std::vector<Iovec>& ciphertext_and_tag,
                        Iovec plaintext) override {
    // Input checks.
    if (plaintext.iov_len != 0) {
      ABSL_ASSERT(plaintext.iov_base != nullptr);
    }

    // Compute the total length of |ciphertext_and_tag| to ensure we do not pass
    // the tag into |EVP_decrypt|.
    size_t total_ciphertext_and_tag_length = 0;
    for (const auto& vec : ciphertext_and_tag) {
      total_ciphertext_and_tag_length += vec.iov_len;
    }
    if (total_ciphertext_and_tag_length < kChachaPolyTagSize) {
      return CrypterStatus(
          absl::InvalidArgumentError(
              "|ciphertext_and_tag| is too small to hold a tag."),
          /*bytes_written=*/0);
    }

    // Init Openssl context using |nonce|.
    absl::Status nonce_status = DecryptInitContextUsingNonce(ctx_.get(), nonce);
    if (!nonce_status.ok()) {
      return CrypterStatus(nonce_status, /*bytes_written=*/0);
    }

    // Set the authentication data using |aad|.
    absl::Status aad_status = SetAadForDecrypt(ctx_.get(), aad);
    if (!aad_status.ok()) {
      return CrypterStatus(aad_status, /*bytes_written=*/0);
    }

    uint8_t* plaintext_ptr = static_cast<uint8_t*>(plaintext.iov_base);
    size_t remaining_plaintext_length = plaintext.iov_len;

    // Decrypt the ciphertext.
    const uint8_t* ciphertext_ptr = nullptr;
    size_t current_ciphertext_length = 0;
    size_t i;
    for (i = 0; i < ciphertext_and_tag.size(); i++) {
      if (total_ciphertext_and_tag_length <= kChachaPolyTagSize) {
        break;
      }

      ciphertext_ptr = static_cast<uint8_t*>(ciphertext_and_tag[i].iov_base);
      current_ciphertext_length = ciphertext_and_tag[i].iov_len;
      if (current_ciphertext_length == 0) {
        continue;
      }
      if (ciphertext_ptr == nullptr) {
        memset(plaintext.iov_base, 0x00, plaintext.iov_len);
        return CrypterStatus(
            absl::InvalidArgumentError(
                "|ciphertext_and_tag| has an invalid component."),
            /*bytes_written=*/0);
      }

      size_t bytes_written = 0;
      size_t bytes_to_write = current_ciphertext_length;
      // Do not include the tag.
      if (bytes_to_write >
          total_ciphertext_and_tag_length - kChachaPolyTagSize) {
        bytes_to_write = total_ciphertext_and_tag_length - kChachaPolyTagSize;
      }
      if (remaining_plaintext_length < bytes_to_write) {
        return CrypterStatus(
            absl::InvalidArgumentError(
                "|plaintext| is too small to hold the decrypted ciphertext."),
            /*bytes_written=*/0);
      }
      if (!EVP_DecryptUpdate(
              ctx_.get(), plaintext_ptr, reinterpret_cast<int*>(&bytes_written),
              ciphertext_ptr, static_cast<int>(bytes_to_write))) {
        memset(plaintext.iov_base, 0x00, plaintext.iov_len);
        return CrypterStatus(
            absl::InternalError("Decrypting ciphertext failed. " +
                                GetSSLErrors()),
            /*bytes_written=*/0);
      }
      if (bytes_written > current_ciphertext_length) {
        memset(plaintext.iov_base, 0x00, plaintext.iov_len);
        return CrypterStatus(
            absl::InternalError("More bytes written than expected. " +
                                GetSSLErrors()),
            /*bytes_written=*/0);
      }
      ciphertext_ptr += bytes_written;
      current_ciphertext_length -= bytes_written;
      total_ciphertext_and_tag_length -= bytes_written;
      plaintext_ptr += bytes_written;
      remaining_plaintext_length -= bytes_written;
    }

    if (total_ciphertext_and_tag_length > kChachaPolyTagSize) {
      memset(plaintext.iov_base, 0x00, plaintext.iov_len);
      return CrypterStatus(
          absl::InternalError(
              "Not enough plaintext buffer to hold encrypted ciphertext. " +
              GetSSLErrors()),
          /*bytes_written=*/0);
    }

    // Check the tag.
    uint8_t tag[kChachaPolyTagSize];
    uint8_t* tag_tmp = tag;
    if (current_ciphertext_length > 0) {
      memcpy(tag_tmp, ciphertext_ptr, current_ciphertext_length);
      tag_tmp += current_ciphertext_length;
      total_ciphertext_and_tag_length -= current_ciphertext_length;
    }
    for (; i < ciphertext_and_tag.size(); i++) {
      ciphertext_ptr = static_cast<uint8_t*>(ciphertext_and_tag[i].iov_base);
      current_ciphertext_length = ciphertext_and_tag[i].iov_len;
      memcpy(tag_tmp, ciphertext_ptr, current_ciphertext_length);
      tag_tmp += current_ciphertext_length;
      total_ciphertext_and_tag_length -= current_ciphertext_length;
    }
    absl::Status tag_status = DecryptCheckTagAndFinalize(
        ctx_.get(), {tag, kChachaPolyTagSize}, plaintext);
    if (!tag_status.ok()) {
      return CrypterStatus(tag_status, /*bytes_written=*/0);
    }
    return CrypterStatus(absl::OkStatus(),
                         plaintext.iov_len - remaining_plaintext_length);
  }

 private:
  std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> ctx_;
};

absl::variant<absl::Status, std::unique_ptr<S2AAeadCrypter>>
CreateChachaPolyAeadCrypter(const std::vector<uint8_t>& key) {
  // Check the key length and, if possible, create the |EVP_CIPHER|.
  if (key.size() != kChachaPolyKeySize) {
    return absl::InvalidArgumentError("Key size is unsupported.");
  }
  const EVP_CIPHER* cipher = nullptr;
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
  cipher = EVP_chacha20_poly1305();
#else
  return absl::FailedPreconditionError(
      "OPENSSL_NO_POLY1305 is defined. Cannot use Chacha20-Poly1305 cipher.");
#endif

  // Create and initialize the cipher context.
  std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> ctx(
      EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (!EVP_DecryptInit_ex(ctx.get(), cipher, /*impl=*/nullptr, key.data(),
                          /*iv=*/nullptr) ||
      !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           static_cast<int>(kChachaPolyNonceSize),
                           /*ptr=*/nullptr)) {
    return absl::InternalError(absl::StrCat(
        "Initialization of |EVP_AEAD_CTX| failed: ", GetSSLErrors()));
  }
  return absl::make_unique<ChachaPolyS2AAeadCrypterOpenSSL>(
      std::move(ctx), key, kChachaPolyNonceSize, kChachaPolyTagSize);
}

}  // namespace aead_crypter
}  // namespace s2a

#endif
