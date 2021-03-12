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
#include <openssl/bio.h>
#include <openssl/err.h>

#include "crypto/s2a_aead_crypter_util.h"

namespace s2a {
namespace aead_crypter {

std::string GetSSLErrors() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  BUF_MEM* mem = nullptr;
  std::string error_msg;
  BIO_get_mem_ptr(bio, &mem);
  if (mem != nullptr) {
    error_msg.assign(mem->data, mem->length);
  }
  BIO_free_all(bio);
  return error_msg;
}

}  // namespace aead_crypter
}  // namespace s2a
