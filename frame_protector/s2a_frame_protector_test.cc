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

#include "frame_protector/s2a_frame_protector.h"

#include <vector>

#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "record_protocol/s2a_crypter_util.h"
#include "s2a_constants.h"
#include "test_util/s2a_test_data.h"

namespace s2a {
namespace frame_protector {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::absl::StatusOr;
using ::s2a::aead_crypter::Iovec;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;
using ::s2a::frame_protector::S2AFrameProtector;
using Result = ::s2a::frame_protector::S2AFrameProtector::Result;
using S2AFrameProtectorOptions =
    ::s2a::frame_protector::S2AFrameProtector::S2AFrameProtectorOptions;

constexpr char kS2AHandshakerServiceUrl[] = "s2a_handshaker_service_url";
constexpr uint8_t kTls12ApplicationData = 0x17;
constexpr uint8_t kTls12WireVersion = 0x03;
constexpr size_t kTls13HeaderLength = 5;
constexpr size_t kTls13MaxPlaintextBytesPerRecord = 16384;
constexpr size_t kTls13RecordOverhead = 22;
constexpr char kTestLocalIdentity[] = "test_local_identity";
constexpr uint64_t kTestConnectionId = 1234;

Iovec Allocator(size_t length) { return {new uint8_t[length], length}; }

void Destroy(Iovec iovec) { delete[] static_cast<uint8_t*>(iovec.iov_base); }

void Logger(const std::string& message) {}

size_t CiphersuiteToHashLength(Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return kSha256DigestLength;
    case Ciphersuite::AES_256_GCM_SHA384:
      return kSha384DigestLength;
    default:  // Ciphersuite is unsupported.
      return 0;
  }
}

struct RecordStatus {
  bool valid_tls_records;
  size_t number_tls_records;
};

RecordStatus ParseTlsRecords(Iovec bytes) {
  if (bytes.iov_base == nullptr || bytes.iov_len < kTls13RecordOverhead) {
    return {/*valid_tls_records=*/false, /*number_tls_records=*/0};
  }
  size_t number_tls_records = 0;
  size_t index = 0;
  while (index < bytes.iov_len) {
    uint8_t* bytes_ptr = static_cast<uint8_t*>(bytes.iov_base);
    if (bytes_ptr[index] != kTls12ApplicationData ||
        bytes_ptr[index + 1] != kTls12WireVersion ||
        bytes_ptr[index + 2] != kTls12WireVersion) {
      return {/*valid_tls_records=*/false, /*number_tls_records=*/0};
    }
    size_t record_size = kTls13HeaderLength +
                         (static_cast<int>(bytes_ptr[index + 3] & 0xff) << 8) +
                         static_cast<int>(bytes_ptr[index + 4] & 0xff);
    index += record_size;
    number_tls_records += 1;
  }
  if (index != bytes.iov_len) {
    return {/*valid_tls_records=*/false, /*number_tls_records=*/0};
  }
  return {/*valid_tls_records=*/true, number_tls_records};
}

struct TestTlsRecord {
  const uint8_t* record;
  size_t record_size;
};

TestTlsRecord GetTestTlsRecord(Ciphersuite ciphersuite) {
  switch (ciphersuite) {
    case Ciphersuite::AES_128_GCM_SHA256:
      return {s2a_test_data::aes_128_gcm_decrypt_record_1,
              s2a_test_data::aes_128_gcm_decrypt_record_1_size};
    case Ciphersuite::AES_256_GCM_SHA384:
      return {s2a_test_data::aes_256_gcm_decrypt_record_1,
              s2a_test_data::aes_256_gcm_decrypt_record_1_size};
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      return {s2a_test_data::chacha_poly_decrypt_record_1,
              s2a_test_data::chacha_poly_decrypt_record_1_size};
    default:
      return {nullptr, 0};
  }
}

TEST(S2AFrameProtectorFailTest, CreateFailsBecauseAllocatorIsNullptr) {
  s2a_options::S2AOptions::Identity local_identity =
      s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity);
  std::vector<uint8_t> traffic_secret(
      CiphersuiteToHashLength(Ciphersuite::AES_128_GCM_SHA256), 0x6b);
  std::string s2a_address = kS2AHandshakerServiceUrl;
  S2AFrameProtectorOptions options = {TlsVersion::TLS1_3,
                                      Ciphersuite::AES_128_GCM_SHA256,
                                      traffic_secret,
                                      traffic_secret,
                                      /*in_sequence=*/0,
                                      /*out_sequence=*/0,
                                      s2a_address,
                                      local_identity,
                                      kTestConnectionId,
                                      /*channel_factory=*/nullptr,
                                      /*channel_options=*/nullptr,
                                      /*allocator=*/nullptr,
                                      Destroy,
                                      Logger};
  StatusOr<std::unique_ptr<S2AFrameProtector>> frame_protector_or =
      S2AFrameProtector::Create(options);
  ASSERT_FALSE(frame_protector_or.ok());
  EXPECT_EQ(frame_protector_or.status(),
            Status(StatusCode::kInvalidArgument,
                   "Failed to create |S2AFrameProtector| because of unexpected "
                   "nullptr argument."));
}

TEST(S2AFrameProtectorFailTest, CreateFailsBecauseDestroyIsNullptr) {
  s2a_options::S2AOptions::Identity local_identity =
      s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity);
  std::vector<uint8_t> traffic_secret(
      CiphersuiteToHashLength(Ciphersuite::AES_128_GCM_SHA256), 0x6b);
  std::string s2a_address = kS2AHandshakerServiceUrl;
  S2AFrameProtectorOptions options = {TlsVersion::TLS1_3,
                                      Ciphersuite::AES_128_GCM_SHA256,
                                      traffic_secret,
                                      traffic_secret,
                                      /*in_sequence=*/0,
                                      /*out_sequence=*/0,
                                      s2a_address,
                                      local_identity,
                                      kTestConnectionId,
                                      /*channel_factory=*/nullptr,
                                      /*channel_options=*/nullptr,
                                      Allocator,
                                      /*destroy=*/nullptr,
                                      Logger};
  StatusOr<std::unique_ptr<S2AFrameProtector>> frame_protector_or =
      S2AFrameProtector::Create(options);
  ASSERT_FALSE(frame_protector_or.ok());
  EXPECT_EQ(frame_protector_or.status(),
            Status(StatusCode::kInvalidArgument,
                   "Failed to create |S2AFrameProtector| because of unexpected "
                   "nullptr argument."));
}

TEST(S2AFrameProtectorFailTest, CreateFailsBecauseLoggerIsNullptr) {
  s2a_options::S2AOptions::Identity local_identity =
      s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity);
  std::vector<uint8_t> traffic_secret(
      CiphersuiteToHashLength(Ciphersuite::AES_128_GCM_SHA256), 0x6b);
  std::string s2a_address = kS2AHandshakerServiceUrl;
  S2AFrameProtectorOptions options = {
      TlsVersion::TLS1_3,
      Ciphersuite::AES_128_GCM_SHA256,
      traffic_secret,
      traffic_secret,
      /*in_sequence=*/0,
      /*out_sequence=*/0,
      s2a_address,
      local_identity,
      kTestConnectionId,
      /*channel_factory=*/nullptr,
      /*channel_options=*/nullptr,
      Allocator,
      Destroy,
      /*logger=*/nullptr,
  };
  StatusOr<std::unique_ptr<S2AFrameProtector>> frame_protector_or =
      S2AFrameProtector::Create(options);
  ASSERT_FALSE(frame_protector_or.ok());
  EXPECT_EQ(frame_protector_or.status(),
            Status(StatusCode::kInvalidArgument,
                   "Failed to create |S2AFrameProtector| because of unexpected "
                   "nullptr argument."));
}

TEST(S2AFrameProtectorFailTest, CreateFailsBecauseEmptyHandshakerServiceUrl) {
  s2a_options::S2AOptions::Identity local_identity =
      s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity);
  std::vector<uint8_t> traffic_secret(
      CiphersuiteToHashLength(Ciphersuite::AES_128_GCM_SHA256), 0x6b);
  S2AFrameProtectorOptions options = {TlsVersion::TLS1_3,
                                      Ciphersuite::AES_128_GCM_SHA256,
                                      traffic_secret,
                                      traffic_secret,
                                      /*in_sequence=*/0,
                                      /*out_sequence=*/0,
                                      /*handshaker_service_url=*/"",
                                      local_identity,
                                      kTestConnectionId,
                                      /*channel_factory=*/nullptr,
                                      /*channel_options=*/nullptr,
                                      Allocator,
                                      Destroy,
                                      Logger};
  StatusOr<std::unique_ptr<S2AFrameProtector>> frame_protector_or =
      S2AFrameProtector::Create(options);
  ASSERT_FALSE(frame_protector_or.ok());
  EXPECT_EQ(frame_protector_or.status(),
            Status(StatusCode::kInvalidArgument,
                   "|handshaker_service_url| is empty."));
}

class S2AFrameProtectorTest : public ::testing::TestWithParam<Ciphersuite> {
 protected:
  S2AFrameProtectorTest() {}

  void SetUp() override {
    s2a_options::S2AOptions::Identity local_identity =
        s2a_options::S2AOptions::Identity::FromHostname(kTestLocalIdentity);
    std::vector<uint8_t> traffic_secret(CiphersuiteToHashLength(GetParam()),
                                        0x6b);
    std::string s2a_address = kS2AHandshakerServiceUrl;
    S2AFrameProtectorOptions options = {TlsVersion::TLS1_3,
                                        GetParam(),
                                        traffic_secret,
                                        traffic_secret,
                                        /*in_sequence=*/0,
                                        /*out_sequence=*/0,
                                        s2a_address,
                                        local_identity,
                                        kTestConnectionId,
                                        /*channel_factory=*/nullptr,
                                        /*channel_options=*/nullptr,
                                        Allocator,
                                        Destroy,
                                        Logger};
    StatusOr<std::unique_ptr<S2AFrameProtector>> frame_protector_or =
        S2AFrameProtector::Create(options);
    ASSERT_TRUE(frame_protector_or.ok());
    frame_protector_ = std::move(*frame_protector_or);
  };

  std::unique_ptr<S2AFrameProtector> frame_protector_;
};

INSTANTIATE_TEST_CASE_P(
    S2AFrameProtectorTest, S2AFrameProtectorTest,
    ::testing::Values(Ciphersuite::AES_128_GCM_SHA256,
                      Ciphersuite::AES_256_GCM_SHA384,
                      Ciphersuite::CHACHA20_POLY1305_SHA256));

TEST_P(S2AFrameProtectorTest, NumberBytesToProtect) {
  Iovec empty_iovec = {nullptr, 0};
  EXPECT_EQ(frame_protector_->NumberBytesToProtect({empty_iovec}),
            kTls13RecordOverhead);

  size_t small_buffer_size = 5;
  std::vector<uint8_t> small_buffer(small_buffer_size);
  EXPECT_EQ(frame_protector_->NumberBytesToProtect(
                {{small_buffer.data(), small_buffer.size()}}),
            small_buffer_size + kTls13RecordOverhead);

  size_t max_buffer_size = kTls13MaxPlaintextBytesPerRecord;
  std::vector<uint8_t> max_buffer(max_buffer_size);
  EXPECT_EQ(frame_protector_->NumberBytesToProtect(
                {{max_buffer.data(), max_buffer.size()}}),
            max_buffer_size + kTls13RecordOverhead);

  EXPECT_EQ(frame_protector_->NumberBytesToProtect(
                {{max_buffer.data(), max_buffer.size()},
                 {small_buffer.data(), small_buffer.size()}}),
            small_buffer_size + max_buffer_size + 2 * kTls13RecordOverhead);

  EXPECT_EQ(frame_protector_->NumberBytesToProtect(
                {{max_buffer.data(), max_buffer.size()},
                 {max_buffer.data(), max_buffer.size()}}),
            2 * (max_buffer_size + kTls13RecordOverhead));
}

TEST_P(S2AFrameProtectorTest, NumberBytesToUnprotect) {
  Iovec empty_iovec = {nullptr, 0};
  EXPECT_EQ(frame_protector_->NumberBytesToUnprotect({empty_iovec}), 0);

  size_t small_buffer_size = kTls13RecordOverhead - 1;
  std::vector<uint8_t> small_buffer(small_buffer_size);
  EXPECT_EQ(frame_protector_->NumberBytesToUnprotect(
                {{small_buffer.data(), small_buffer.size()}}),
            0);

  size_t large_buffer_size =
      kTls13MaxPlaintextBytesPerRecord + kTls13RecordOverhead;
  std::vector<uint8_t> large_buffer(large_buffer_size);
  EXPECT_EQ(frame_protector_->NumberBytesToUnprotect(
                {{large_buffer.data(), large_buffer.size()}}),
            large_buffer_size - kTls13HeaderLength);
}

TEST_P(S2AFrameProtectorTest, ProtectSmallBuffer) {
  std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
  Iovec plaintext_iovec = {plaintext.data(), plaintext.size()};
  Result result = frame_protector_->Protect({plaintext_iovec});
  ASSERT_TRUE(result.status.ok());
  ASSERT_EQ(result.bytes.size(), 1);

  TestTlsRecord record = GetTestTlsRecord(GetParam());
  ASSERT_EQ(result.bytes[0].iov_len, record.record_size);
  for (size_t i = 0; i < record.record_size; i++) {
    EXPECT_EQ(static_cast<uint8_t*>(result.bytes[0].iov_base)[i],
              record.record[i]);
  }

  Destroy(result.bytes[0]);
}

TEST_P(S2AFrameProtectorTest, ProtectSmallBufferWithCustomAllocation) {
  std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
  Iovec plaintext_iovec = {plaintext.data(), plaintext.size()};
  size_t record_length =
      frame_protector_->NumberBytesToProtect(plaintext.size());
  Iovec record_vec = {new uint8_t[record_length], record_length};

  Status status = frame_protector_->Protect({plaintext_iovec}, record_vec);
  ASSERT_TRUE(status.ok());

  TestTlsRecord record = GetTestTlsRecord(GetParam());
  ASSERT_EQ(record_vec.iov_len, record.record_size);
  for (size_t i = 0; i < record.record_size; i++) {
    EXPECT_EQ(static_cast<uint8_t*>(record_vec.iov_base)[i], record.record[i]);
  }

  Destroy(record_vec);
}

TEST_P(S2AFrameProtectorTest, ProtectEmptyBuffer) {
  std::vector<uint8_t> plaintext = {};
  Iovec plaintext_iovec = {plaintext.data(), plaintext.size()};
  Result result = frame_protector_->Protect({plaintext_iovec});
  ASSERT_TRUE(result.status.ok());
  ASSERT_EQ(result.bytes.size(), 1);

  const uint8_t* record;
  size_t record_size;
  switch (GetParam()) {
    case Ciphersuite::AES_128_GCM_SHA256:
      record = s2a_test_data::aes_128_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_128_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      record = s2a_test_data::aes_256_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_256_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      record = s2a_test_data::chacha_poly_empty_record_bytes;
      record_size = s2a_test_data::chacha_poly_empty_record_bytes_size;
      break;
  }
  ASSERT_EQ(result.bytes[0].iov_len, record_size);
  for (size_t i = 0; i < record_size; i++) {
    EXPECT_EQ(static_cast<uint8_t*>(result.bytes[0].iov_base)[i], record[i])
        << "Index i=" << i;
  }

  Destroy(result.bytes[0]);
}

TEST_P(S2AFrameProtectorTest, ProtectEmptyBufferWithCustomAllocation) {
  std::vector<uint8_t> plaintext = {};
  Iovec plaintext_iovec = {plaintext.data(), plaintext.size()};
  size_t record_length =
      frame_protector_->NumberBytesToProtect(/*unprotected_bytes_length=*/0);
  Iovec record_vec = {new uint8_t[record_length], record_length};

  Status status = frame_protector_->Protect({plaintext_iovec}, record_vec);
  ASSERT_TRUE(status.ok());

  const uint8_t* record;
  size_t record_size;
  switch (GetParam()) {
    case Ciphersuite::AES_128_GCM_SHA256:
      record = s2a_test_data::aes_128_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_128_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      record = s2a_test_data::aes_256_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_256_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      record = s2a_test_data::chacha_poly_empty_record_bytes;
      record_size = s2a_test_data::chacha_poly_empty_record_bytes_size;
      break;
  }
  ASSERT_EQ(record_vec.iov_len, record_size);
  for (size_t i = 0; i < record_size; i++) {
    EXPECT_EQ(static_cast<uint8_t*>(record_vec.iov_base)[i], record[i])
        << "Index i=" << i;
  }

  Destroy(record_vec);
}

TEST_P(S2AFrameProtectorTest, ProtectLargeContiguousBuffers) {
  const struct {
    std::string description;
    size_t number_of_unprotected_bytes;
    size_t number_of_protected_bytes;
    size_t number_of_tls_records;
    bool custom_preallocation;
  } tests[] = {
      {"0 bytes.", 0u, kTls13RecordOverhead, 1u, false},
      {"5 bytes.", 5u, 5u + kTls13RecordOverhead, 1u, false},
      {"1 max size record.", kTls13MaxPlaintextBytesPerRecord,
       kTls13MaxPlaintextBytesPerRecord + kTls13RecordOverhead, 1u, false},
      {"1 max size record plus 5 bytes.", kTls13MaxPlaintextBytesPerRecord + 5u,
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead, 2u,
       false},
      {"2 max size records.", 2 * kTls13MaxPlaintextBytesPerRecord,
       2 * kTls13MaxPlaintextBytesPerRecord + 2 * kTls13RecordOverhead, 2u,
       false},
      {"2 max size records plus 5 bytes.",
       2 * kTls13MaxPlaintextBytesPerRecord + 5u,
       2 * kTls13MaxPlaintextBytesPerRecord + 5u + 3 * kTls13RecordOverhead, 3u,
       false},
      {"0 bytes, with custom preallocation.", 0u, kTls13RecordOverhead, 1u,
       true},
      {"5 bytes, with custom preallocation.", 5u, 5u + kTls13RecordOverhead, 1u,
       true},
      {"1 max size record, with custom preallocation.",
       kTls13MaxPlaintextBytesPerRecord,
       kTls13MaxPlaintextBytesPerRecord + kTls13RecordOverhead, 1u, true},
      {"1 max size record plus 5 bytes, with custom preallocation.",
       kTls13MaxPlaintextBytesPerRecord + 5u,
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead, 2u,
       true},
      {"2 max size records, with custom preallocation.",
       2 * kTls13MaxPlaintextBytesPerRecord,
       2 * kTls13MaxPlaintextBytesPerRecord + 2 * kTls13RecordOverhead, 2u,
       true},
      {"2 max size records plus 5 bytes, with custom preallocation.",
       2 * kTls13MaxPlaintextBytesPerRecord + 5u,
       2 * kTls13MaxPlaintextBytesPerRecord + 5u + 3 * kTls13RecordOverhead, 3u,
       true},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    std::vector<uint8_t> unprotected_bytes(
        tests[i].number_of_unprotected_bytes);
    size_t record_length = frame_protector_->NumberBytesToProtect(
        tests[i].number_of_unprotected_bytes);
    Iovec record_vec;

    if (tests[i].custom_preallocation) {
      record_vec = {new uint8_t[record_length], record_length};
      Status status = frame_protector_->Protect(
          {{unprotected_bytes.data(), unprotected_bytes.size()}}, record_vec);
      ASSERT_TRUE(status.ok()) << tests[i].description;
    } else {
      Result result = frame_protector_->Protect(
          {{unprotected_bytes.data(), unprotected_bytes.size()}});
      ASSERT_TRUE(result.status.ok()) << tests[i].description;
      ASSERT_EQ(result.bytes.size(), 1) << tests[i].description;
      record_vec = result.bytes[0];
    }
    EXPECT_EQ(record_vec.iov_len, tests[i].number_of_protected_bytes)
        << tests[i].description;

    RecordStatus status = ParseTlsRecords(record_vec);
    EXPECT_TRUE(status.valid_tls_records) << tests[i].description;
    EXPECT_EQ(status.number_tls_records, tests[i].number_of_tls_records)
        << tests[i].description;

    // Cleanup.
    Destroy(record_vec);
  }
}

TEST_P(S2AFrameProtectorTest, ProtectLargeFragmentedBuffers) {
  const struct {
    std::string description;
    std::vector<size_t> iovec_lengths;
    size_t number_of_protected_bytes;
    size_t number_of_tls_records;
    bool custom_preallocation;
  } tests[] = {
      {"5 Iovec's of length 0.",
       {0, 0, 0, 0, 0},
       kTls13RecordOverhead,
       1u,
       false},
      {"5 Iovec's of length 1.",
       {1, 1, 1, 1, 1},
       5u + kTls13RecordOverhead,
       1u,
       false},
      {"4 Iovec's of length 1 with a length 0 Iovec in the middle.",
       {1, 1, 0, 1, 1},
       4u + kTls13RecordOverhead,
       1u,
       false},
      {"Max length followed by length 5.",
       {kTls13MaxPlaintextBytesPerRecord, 5u},
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead,
       2u,
       false},
      {"Length 5 followed by max length.",
       {5, kTls13MaxPlaintextBytesPerRecord},
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead,
       2u,
       false},
      {"5 Iovec's of length 1 followed by max length.",
       {1, 1, 1, 1, 1, kTls13MaxPlaintextBytesPerRecord},
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead,
       2u,
       false},
      {"5 Iovec's of length 0, with custom preallocation.",
       {0, 0, 0, 0, 0},
       kTls13RecordOverhead,
       1u,
       true},
      {"5 Iovec's of length 1, with custom preallocation.",
       {1, 1, 1, 1, 1},
       5u + kTls13RecordOverhead,
       1u,
       true},
      {"4 Iovec's of length 1 with a length 0 Iovec in the middle, with custom "
       "preallocation.",
       {1, 1, 0, 1, 1},
       4u + kTls13RecordOverhead,
       1u,
       true},
      {"Max length followed by length 5, with custom preallocation.",
       {kTls13MaxPlaintextBytesPerRecord, 5u},
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead,
       2u,
       true},
      {"Length 5 followed by max length, with custom preallocation.",
       {5, kTls13MaxPlaintextBytesPerRecord},
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead,
       2u,
       true},
      {"5 Iovec's of length 1 followed by max length, with custom "
       "preallocation.",
       {1, 1, 1, 1, 1, kTls13MaxPlaintextBytesPerRecord},
       kTls13MaxPlaintextBytesPerRecord + 5u + 2 * kTls13RecordOverhead,
       2u,
       true},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    std::vector<Iovec> unprotected_bytes;
    for (size_t length : tests[i].iovec_lengths) {
      unprotected_bytes.push_back(Allocator(length));
    }
    size_t record_length =
        frame_protector_->NumberBytesToProtect(unprotected_bytes);
    Iovec record_vec;

    if (tests[i].custom_preallocation) {
      record_vec = {new uint8_t[record_length], record_length};
      Status status = frame_protector_->Protect(unprotected_bytes, record_vec);
      ASSERT_TRUE(status.ok()) << tests[i].description;
    } else {
      Result result = frame_protector_->Protect(unprotected_bytes);
      ASSERT_TRUE(result.status.ok()) << tests[i].description;
      ASSERT_EQ(result.bytes.size(), 1) << tests[i].description;
      record_vec = result.bytes[0];
    }
    EXPECT_EQ(record_vec.iov_len, tests[i].number_of_protected_bytes)
        << tests[i].description;

    RecordStatus status = ParseTlsRecords(record_vec);
    EXPECT_TRUE(status.valid_tls_records) << tests[i].description;
    EXPECT_EQ(status.number_tls_records, tests[i].number_of_tls_records)
        << tests[i].description;

    // Cleanup.
    Destroy(record_vec);
    for (auto& vec : unprotected_bytes) {
      Destroy(vec);
    }
  }
}

TEST_P(S2AFrameProtectorTest, UnprotectFailureBecauseDoNotHaveFullRecord) {
  std::vector<uint8_t> small_record(kTls13RecordOverhead - 1);
  Iovec unprotected_bytes = {small_record.data(), small_record.size()};

  Result result = frame_protector_->Unprotect({unprotected_bytes});
  ASSERT_EQ(result.status,
            Status(StatusCode::kFailedPrecondition,
                   "|protected_bytes| is too small to contain a TLS record."));
  ASSERT_TRUE(result.bytes.empty());
}

TEST_P(S2AFrameProtectorTest, UnprotectFailureBecauseHeaderTypeIsBad) {
  // Change the first byte of the TLS record so that type of the TLS record is
  // unrecognized.
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  std::vector<uint8_t> bad_record(record.record_size);
  memcpy(bad_record.data(), record.record, record.record_size);
  // It only matters that |bad_record[0]| != |kTls12ApplicationData|, which is
  // the byte that indicates a TLS 1.2 application data record type.
  bad_record[0] = 0x00;
  Iovec unprotected_bytes = {bad_record.data(), bad_record.size()};

  Result result = frame_protector_->Unprotect({unprotected_bytes});
  ASSERT_EQ(result.status,
            Status(StatusCode::kFailedPrecondition,
                   "TLS record header is incorrectly formatted."));
  ASSERT_TRUE(result.bytes.empty());
}

TEST_P(S2AFrameProtectorTest, UnprotectFailureBecauseHeaderWireVersionIsBad) {
  // Change the second byte of the TLS record so that wire version of the TLS
  // record is unrecognized.
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  std::vector<uint8_t> bad_record(record.record_size);
  memcpy(bad_record.data(), record.record, record.record_size);
  // It only matters that |bad_record[1]| != |kTls12WireVersion|, which is the
  // byte that indicates the TLS 1.2 wire version.
  bad_record[1] = 0x00;
  Iovec unprotected_bytes = {bad_record.data(), bad_record.size()};

  Result result = frame_protector_->Unprotect({unprotected_bytes});
  ASSERT_EQ(result.status,
            Status(StatusCode::kFailedPrecondition,
                   "TLS record header is incorrectly formatted."));
  ASSERT_TRUE(result.bytes.empty());
}

TEST_P(S2AFrameProtectorTest,
       UnprotectWithCustomPreallocationFailureBecauseHeaderWireVersionIsBad) {
  // Change the second byte of the TLS record so that wire version of the TLS
  // record is unrecognized.
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  std::vector<uint8_t> bad_record(record.record_size);
  memcpy(bad_record.data(), record.record, record.record_size);
  // It only matters that |bad_record[1]| != |kTls12WireVersion|, which is the
  // byte that indicates the TLS 1.2 wire version.
  bad_record[1] = 0x00;
  Iovec unprotected_bytes = {bad_record.data(), bad_record.size()};
  Iovec plaintext;

  Status status = frame_protector_->Unprotect({unprotected_bytes}, plaintext);
  ASSERT_EQ(status, Status(StatusCode::kFailedPrecondition,
                           "TLS record header is incorrectly formatted."));
}

TEST_P(S2AFrameProtectorTest,
       UnprotectWithCustomPreallocationFailureBecausePartialRecord) {
  std::vector<uint8_t> incomplete_record(kTls13RecordOverhead - 1);
  Iovec plaintext;
  Status status = frame_protector_->Unprotect(
      {{incomplete_record.data(), incomplete_record.size()}}, plaintext);
  ASSERT_EQ(status,
            Status(StatusCode::kFailedPrecondition,
                   "|protected_bytes| is too small to contain a TLS record."));
}

TEST_P(S2AFrameProtectorTest, UnprotectDecryptionFailure) {
  // Change the last byte of the TLS record so that tag cannot be authenticated.
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  std::vector<uint8_t> bad_record(record.record_size);
  memcpy(bad_record.data(), record.record, record.record_size);
  bad_record[bad_record.size() - 1] += 1;
  Iovec unprotected_bytes = {bad_record.data(), bad_record.size()};

  Result result = frame_protector_->Unprotect({unprotected_bytes});
  ASSERT_EQ(result.status.code(), StatusCode::kInternal);
  ASSERT_TRUE(result.bytes.empty());
}

TEST_P(S2AFrameProtectorTest,
       UnprotectWithCustomPreallocationDecryptionFailure) {
  // Change the last byte of the TLS record so that tag cannot be authenticated.
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  std::vector<uint8_t> bad_record(record.record_size);
  memcpy(bad_record.data(), record.record, record.record_size);
  bad_record[bad_record.size() - 1] += 1;
  Iovec unprotected_bytes = {bad_record.data(), bad_record.size()};
  std::vector<uint8_t> plaintext(
      frame_protector_->NumberBytesToUnprotect(bad_record.size()));
  Iovec plaintext_vec = {plaintext.data(), plaintext.size()};

  Status status =
      frame_protector_->Unprotect({unprotected_bytes}, plaintext_vec);
  ASSERT_EQ(status.code(), StatusCode::kInternal);
  ASSERT_EQ(plaintext_vec.iov_len, 0);
}

TEST_P(S2AFrameProtectorTest, UnprotectSmallBuffer) {
  // Prepare the TLS record.
  std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  Iovec protected_bytes = {const_cast<uint8_t*>(record.record),
                           record.record_size};

  Result result = frame_protector_->Unprotect({protected_bytes});
  ASSERT_TRUE(result.status.ok()) << result.status.message();
  ASSERT_EQ(result.bytes.size(), 1);
  EXPECT_EQ(result.bytes[0].iov_len, plaintext.size());
  for (size_t i = 0; i < plaintext.size(); i++) {
    EXPECT_EQ(static_cast<uint8_t*>(result.bytes[0].iov_base)[i], plaintext[i]);
  }

  Destroy(result.bytes[0]);
}

TEST_P(S2AFrameProtectorTest, UnprotectSmallBufferWithCustomPreallocation) {
  // Prepare the TLS record.
  std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
  TestTlsRecord record = GetTestTlsRecord(GetParam());
  Iovec protected_bytes = {const_cast<uint8_t*>(record.record),
                           record.record_size};
  std::vector<uint8_t> unprotected_buffer(
      frame_protector_->NumberBytesToUnprotect(protected_bytes.iov_len));
  Iovec unprotected_vec = {unprotected_buffer.data(),
                           unprotected_buffer.size()};

  Status status =
      frame_protector_->Unprotect({protected_bytes}, unprotected_vec);
  ASSERT_TRUE(status.ok()) << status.message();
  EXPECT_EQ(unprotected_vec.iov_len, plaintext.size());
  for (size_t i = 0; i < plaintext.size(); i++) {
    EXPECT_EQ(static_cast<uint8_t*>(unprotected_vec.iov_base)[i], plaintext[i]);
  }
}

TEST_P(S2AFrameProtectorTest, UnprotectEmptyBuffer) {
  // Prepare the TLS record.
  const uint8_t* record;
  size_t record_size;
  switch (GetParam()) {
    case Ciphersuite::AES_128_GCM_SHA256:
      record = s2a_test_data::aes_128_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_128_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      record = s2a_test_data::aes_256_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_256_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      record = s2a_test_data::chacha_poly_empty_record_bytes;
      record_size = s2a_test_data::chacha_poly_empty_record_bytes_size;
      break;
  }
  Iovec protected_bytes = {const_cast<uint8_t*>(record), record_size};

  Result result = frame_protector_->Unprotect({protected_bytes});
  ASSERT_TRUE(result.status.ok()) << result.status.message();
  ASSERT_EQ(result.bytes.size(), 1);
  EXPECT_EQ(result.bytes[0].iov_len, 0);

  Destroy(result.bytes[0]);
}

TEST_P(S2AFrameProtectorTest, UnprotectEmptyBufferWithCustomPreallocation) {
  // Prepare the TLS record.
  const uint8_t* record;
  size_t record_size;
  switch (GetParam()) {
    case Ciphersuite::AES_128_GCM_SHA256:
      record = s2a_test_data::aes_128_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_128_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::AES_256_GCM_SHA384:
      record = s2a_test_data::aes_256_gcm_empty_record_bytes;
      record_size = s2a_test_data::aes_256_gcm_empty_record_bytes_size;
      break;
    case Ciphersuite::CHACHA20_POLY1305_SHA256:
      record = s2a_test_data::chacha_poly_empty_record_bytes;
      record_size = s2a_test_data::chacha_poly_empty_record_bytes_size;
      break;
  }
  Iovec protected_bytes = {const_cast<uint8_t*>(record), record_size};
  std::vector<uint8_t> unprotected_buffer(
      frame_protector_->NumberBytesToUnprotect(protected_bytes.iov_len));
  Iovec unprotected_vec = {unprotected_buffer.data(),
                           unprotected_buffer.size()};

  Status status =
      frame_protector_->Unprotect({protected_bytes}, unprotected_vec);
  ASSERT_TRUE(status.ok()) << status.message();
  EXPECT_EQ(unprotected_vec.iov_len, 0);
}

void UnprotectFragmentedRecord(
    Ciphersuite ciphersuite, std::unique_ptr<S2AFrameProtector> frame_protector,
    const std::vector<uint8_t>& break_indices) {
  std::vector<uint8_t> plaintext = {'1', '2', '3', '4', '5', '6'};
  TestTlsRecord record = GetTestTlsRecord(ciphersuite);
  std::vector<Iovec> protected_bytes;
  for (size_t j = 0; j < break_indices.size(); j++) {
    size_t break_length = j != break_indices.size() - 1
                              ? break_indices[j + 1] - break_indices[j]
                              : record.record_size - break_indices[j];
    protected_bytes.push_back(
        {const_cast<uint8_t*>(record.record) + break_indices[j], break_length});
  }

  Result result = frame_protector->Unprotect({protected_bytes});
  ASSERT_TRUE(result.status.ok()) << result.status.message();
  ASSERT_EQ(result.bytes.size(), 1);
  EXPECT_EQ(result.bytes[0].iov_len, plaintext.size());
  for (size_t i = 0; i < plaintext.size(); i++) {
    EXPECT_EQ(static_cast<uint8_t*>(result.bytes[0].iov_base)[i], plaintext[i]);
  }

  Destroy(result.bytes[0]);
}

TEST_P(S2AFrameProtectorTest, UnprotectFragmentedRecordIntoHeaderAndPayload) {
  UnprotectFragmentedRecord(GetParam(), std::move(frame_protector_),
                            {{0u, 5u, 22u}});
}

TEST_P(S2AFrameProtectorTest,
       UnprotectFragmentedRecordIntoHeaderWithPartOfPayload) {
  UnprotectFragmentedRecord(GetParam(), std::move(frame_protector_),
                            {{0u, 6u, 20u, 22u}});
}

TEST_P(S2AFrameProtectorTest,
       UnprotectFragmentedRecordWithHeaderCompletelyBrokenUp) {
  UnprotectFragmentedRecord(GetParam(), std::move(frame_protector_),
                            {{0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u}});
}

// TODO(matthewstevenson88) Add test cases where |protected_bytes| has >1
// records.

TEST_P(S2AFrameProtectorTest, Roundtrip) {
  const struct {
    size_t message_size;
    size_t number_of_tls_records;
  } tests[] = {
      {0, 1},
      {1, 1},
      {kTls13MaxPlaintextBytesPerRecord - 1u, 1},
      {kTls13MaxPlaintextBytesPerRecord, 1},
      {kTls13MaxPlaintextBytesPerRecord + 1u, 2},
      {2 * kTls13MaxPlaintextBytesPerRecord - 1u, 2},
      {2 * kTls13MaxPlaintextBytesPerRecord, 2},
      {2 * kTls13MaxPlaintextBytesPerRecord + 1u, 3},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    std::vector<uint8_t> message(tests[i].message_size);
    Result protect_result =
        frame_protector_->Protect({{message.data(), message.size()}});
    ASSERT_TRUE(protect_result.status.ok())
        << "Message size: " << tests[i].message_size;
    ASSERT_EQ(protect_result.bytes.size(), 1)
        << "Message size: " << tests[i].message_size;

    Result unprotect_result = frame_protector_->Unprotect(protect_result.bytes);
    ASSERT_TRUE(unprotect_result.status.ok())
        << "Message size: " << tests[i].message_size;
    ASSERT_EQ(unprotect_result.bytes.size(), tests[i].number_of_tls_records)
        << "Message size: " << tests[i].message_size;

    // Ensure that |unprotect_result.bytes| has |size| bytes in total, and each
    // byte is zero (i.e. the same as |message|).
    int bytes_remaining = tests[i].message_size;
    for (auto& vec : unprotect_result.bytes) {
      bytes_remaining -= vec.iov_len;
      for (size_t i = 0; i < vec.iov_len; i++) {
        EXPECT_EQ(static_cast<uint8_t*>(vec.iov_base)[i], 0);
      }
    }
    EXPECT_EQ(bytes_remaining, 0);

    Destroy(protect_result.bytes[0]);
    for (auto& vec : unprotect_result.bytes) {
      Destroy(vec);
    }
  }
}

}  // namespace
}  // namespace frame_protector
}  // namespace s2a
