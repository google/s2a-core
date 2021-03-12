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

#include "crypto/hkdf.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace s2a {
namespace hkdf {

using ::absl::Status;
using ::absl::StatusCode;

static Status HkdfDerivation(HMAC_CTX* hmac, const EVP_MD* digest,
                             const size_t digest_size, size_t n,
                             uint8_t* buffer, const std::vector<uint8_t>& prk,
                             const std::vector<uint8_t>& info,
                             std::vector<uint8_t>& out) {
  if (!HMAC_Init_ex(hmac, prk.data(), prk.size(), digest, /*impl=*/nullptr)) {
    return Status(StatusCode::kInternal, "Initializing HMAC failed.");
  }
  size_t done = 0;
  for (size_t i = 0; i < n; i++) {
    if (i != 0 &&
        (!HMAC_Init_ex(hmac, /*key=*/nullptr, /*key_len=*/0, /*md=*/nullptr,
                       /*impl=*/nullptr) ||
         !HMAC_Update(hmac, buffer, digest_size))) {
      return Status(StatusCode::kInternal, "Updating HMAC failed.");
    }
    uint8_t ctr = i + 1;
    if (!HMAC_Update(hmac, info.data(), info.size()) ||
        !HMAC_Update(hmac, &ctr, /*data_len=*/1) ||
        !HMAC_Final(hmac, buffer, /*out_len=*/nullptr)) {
      return Status(StatusCode::kInternal,
                    "Updating and finalizing HMAC failed.");
    }
    size_t todo = digest_size;
    if (done + todo > out.size()) {
      todo = out.size() - done;
    }
    memcpy(out.data() + done, buffer, todo);
    done += todo;
  }
  return Status();
}

Status HkdfDeriveSecret(HashFunction hash_function,
                        const std::vector<uint8_t>& prk,
                        const std::vector<uint8_t>& info,
                        std::vector<uint8_t>& out) {
  const EVP_MD* digest;
  switch (hash_function) {
    case HashFunction::SHA256_hash_function:
      digest = EVP_sha256();
      break;
    case HashFunction::SHA384_hash_function:
      digest = EVP_sha384();
      break;
    default:
      return Status(StatusCode::kInvalidArgument,
                    "|hash_function| is not supported.");
  }
  const size_t digest_size = EVP_MD_size(digest);
  if (prk.size() < digest_size) {
    return Status(StatusCode::kInvalidArgument,
                  "The size of |prk| must be at least the digest size of "
                  "|hash_function|.");
  }
  uint8_t buf[EVP_MAX_MD_SIZE];
  size_t number_of_blocks = (out.size() + digest_size - 1) / digest_size;
  if (out.size() + digest_size < out.size() || number_of_blocks > 255) {
    return Status(StatusCode::kInternal, "Extracting too many bytes.");
  }
  Status status = Status();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  HMAC_CTX hmac;
  HMAC_CTX_init(&hmac);
  status = HkdfDerivation(&hmac, digest, digest_size, number_of_blocks, buf,
                          prk, info, out);
  HMAC_CTX_cleanup(&hmac);
#else
  HMAC_CTX* hmac = HMAC_CTX_new();
  if (hmac == nullptr) {
    return Status(StatusCode::kInternal,
                  "Could not generate new HMAC context.");
  }
  status = HkdfDerivation(hmac, digest, digest_size, number_of_blocks, buf, prk,
                          info, out);
  HMAC_CTX_free(hmac);
#endif
  return status;
}

}  // namespace hkdf
}  // namespace s2a
