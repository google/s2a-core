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

#include <algorithm>
#include <cmath>

#include "absl/strings/str_format.h"
#include "record_protocol/s2a_crypter.h"
#include "record_protocol/s2a_crypter_util.h"
#include "record_protocol/s2a_ticket_sender.h"
#include "s2a_constants.h"

namespace s2a {

using ::absl::Status;
using ::absl::StatusCode;
using ::absl::StatusOr;
using ::s2a::aead_crypter::Iovec;
using ::s2a::record_protocol::S2ACrypter;
using RecordType = ::s2a::record_protocol::S2ACrypter::RecordType;
using Result = ::s2a::frame_protector::S2AFrameProtector::Result;
using S2ACrypterStatus = ::s2a::record_protocol::S2ACrypter::S2ACrypterStatus;
using S2ACrypterStatusCode =
    ::s2a::record_protocol::S2ACrypter::S2ACrypterStatusCode;
using S2AFrameProtectorOptions =
    ::s2a::frame_protector::S2AFrameProtector::S2AFrameProtectorOptions;

constexpr uint8_t kTls12ApplicationData = 0x17;
constexpr uint8_t kTls12WireVersion = 0x03;
constexpr size_t kTls13RecordHeaderLength = 5;
constexpr size_t kTls13MaxPlaintextBytesPerRecord = 16384;

namespace frame_protector {
namespace {

StatusCode ConvertStatusCode(S2ACrypterStatusCode code) {
  switch (code) {
    case S2ACrypterStatusCode::OK:
      return StatusCode::kOk;
    case S2ACrypterStatusCode::FAILED_PRECONDITION:
      return StatusCode::kFailedPrecondition;
    case S2ACrypterStatusCode::INVALID_ARGUMENT:
      return StatusCode::kInvalidArgument;
    case S2ACrypterStatusCode::UNKNOWN:
      return StatusCode::kUnknown;
    case S2ACrypterStatusCode::UNIMPLEMENTED:
      return StatusCode::kUnimplemented;
    default:
      return StatusCode::kInternal;
  }
}

size_t GetTotalIovecLength(const std::vector<Iovec>& vec) {
  size_t total_length = 0;
  for (auto& iovec : vec) {
    total_length += iovec.iov_len;
  }
  return total_length;
}

struct ComputeTlsRecordSizeResult {
  size_t record_size;
  size_t iovec_index;
  size_t on_vec_index;
};

// |ComputeTlsRecordSize| computes the size of the TLS record stored in |vecs|
// with head at |vecs[vec_index].iov_base[on_vec_index]|, and writes the TLS
// record header to |header|. Further, the |ComputeTlsRecordSizeResult| is
// constructed so that |vecs[iovec_index].iov_base[on_vec_index]| points to the
// start of the TLS payload. The caller must ensure that |header| points to a
// buffer of size >= |kTls13RecordHeaderLength|.
absl::variant<Status, ComputeTlsRecordSizeResult> ComputeTlsRecordSize(
    const std::vector<Iovec>& vecs, size_t vec_index, size_t on_vec_index,
    uint8_t* header) {
  ABSL_ASSERT(header != nullptr);
  size_t header_index = 0;
  size_t iovec_index = vec_index;
  size_t on_iovec_index = on_vec_index;
  size_t first_payload_component;
  size_t second_payload_component;
  while (header_index < kTls13RecordHeaderLength) {
    if (iovec_index >= vecs.size()) {
      return Status(StatusCode::kFailedPrecondition,
                    "|vecs| is too small to hold TLS record header.");
    }
    ABSL_ASSERT(vecs[iovec_index].iov_base != nullptr);
    uint8_t* buffer = static_cast<uint8_t*>(vecs[iovec_index].iov_base);
    size_t buffer_length = vecs[iovec_index].iov_len;
    switch (header_index) {
      case 0:
        if (buffer[on_iovec_index] != kTls12ApplicationData) {
          return Status(StatusCode::kFailedPrecondition,
                        "TLS record header is incorrectly formatted.");
        }
        break;
      case 1:
      case 2:
        if (buffer[on_iovec_index] != kTls12WireVersion) {
          return Status(StatusCode::kFailedPrecondition,
                        "TLS record header is incorrectly formatted.");
        }
        break;
      case 3:
        first_payload_component =
            static_cast<int>(buffer[on_iovec_index] & 0xff) << 8;
        break;
      case 4:
        second_payload_component =
            static_cast<int>(buffer[on_iovec_index] & 0xff);
        break;
      default:
        return Status(StatusCode::kInternal, "Header index is too large.");
    }
    header[header_index] = buffer[on_iovec_index];
    header_index += 1;
    on_iovec_index += 1;
    if (on_iovec_index >= buffer_length) {
      iovec_index += 1;
      on_iovec_index = 0;
    }
  }
  return ComputeTlsRecordSizeResult{kTls13RecordHeaderLength +
                                        first_payload_component +
                                        second_payload_component,
                                    iovec_index, on_iovec_index};
}

struct IsolateTlsPayloadResult {
  std::vector<Iovec> payload;
  size_t vec_index;
  size_t on_vec_index;
};

// |IsolateTlsPayload| constructs a vector of |Iovec|'s that contain exactly the
// TLS payload that starts at |vecs[vec_index].iov_base[on_vec_index]|. Further,
// the |IsolateTlsPayloadResult| is constructed such that
// |vecs[vec_index].iov_base[on_vec_index]| points to the start of the next TLS
// record stored in |vecs|.
absl::variant<Status, IsolateTlsPayloadResult> IsolateTlsPayload(
    const std::vector<Iovec>& vecs, size_t vec_index, size_t on_vec_index,
    size_t payload_size) {
  std::vector<Iovec> payload;
  size_t iovec_index = vec_index;
  size_t on_iovec_index = on_vec_index;
  size_t bytes_remaining = payload_size;
  while (bytes_remaining > 0) {
    if (iovec_index >= vecs.size()) {
      return Status(StatusCode::kFailedPrecondition,
                    "|vecs| is too small to hold TLS record.");
    }
    ABSL_ASSERT(vecs[iovec_index].iov_base != nullptr);
    uint8_t* buffer = static_cast<uint8_t*>(vecs[iovec_index].iov_base);
    size_t bytes_remaining_on_iovec =
        std::min(vecs[iovec_index].iov_len - on_iovec_index, bytes_remaining);
    payload.push_back({buffer + on_iovec_index, bytes_remaining_on_iovec});
    bytes_remaining -= bytes_remaining_on_iovec;
    if (bytes_remaining_on_iovec + on_iovec_index ==
        vecs[iovec_index].iov_len) {
      // All the rest of |vecs[iovec_index]| was added to |plaintext|, so go to
      // the next |Iovec|.
      iovec_index += 1;
      on_iovec_index = 0;
    } else {
      // There are bytes on |vecs[iovec_index]| that are part of the next TLS
      // record.
      on_iovec_index += bytes_remaining_on_iovec;
    }
  }
  return IsolateTlsPayloadResult{payload, iovec_index, on_iovec_index};
}

}  // namespace

StatusOr<std::unique_ptr<S2AFrameProtector>> S2AFrameProtector::Create(
    S2AFrameProtectorOptions& options) {
  if (options.allocator == nullptr || options.destroy == nullptr ||
      options.logger == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "Failed to create |S2AFrameProtector| because of unexpected "
                  "nullptr argument.");
  }
  absl::variant<absl::Status, std::unique_ptr<S2ACrypter>> crypter_status =
      S2ACrypter::Create(options.tls_version, options.tls_ciphersuite,
                         options.connection_id, options.handshaker_service_url,
                         options.local_identity, options.in_traffic_secret,
                         options.out_traffic_secret, options.in_sequence,
                         options.out_sequence,
                         s2a_ticket_sender::SendTicketsToS2A,
                         std::move(options.channel_factory),
                         std::move(options.channel_options), options.logger);
  switch (crypter_status.index()) {
    case 0:
      return absl::get<0>(crypter_status);
    case 1:
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }
  return absl::WrapUnique(
      new S2AFrameProtector(options.allocator, options.destroy, options.logger,
                            std::move(absl::get<1>(crypter_status))));
}

S2AFrameProtector::S2AFrameProtector(
    std::function<Iovec(size_t)> allocator, std::function<void(Iovec)> destroy,
    std::function<void(const std::string&)> logger,
    std::unique_ptr<record_protocol::S2ACrypter> crypter)
    : allocator_(allocator),
      destroy_(destroy),
      logger_(logger),
      max_record_size_(kTls13MaxPlaintextBytesPerRecord +
                       crypter->RecordOverhead()),
      crypter_(std::move(crypter)) {}

Result S2AFrameProtector::Protect(const std::vector<Iovec>& unprotected_bytes) {
  Iovec protected_bytes = allocator_(NumberBytesToProtect(unprotected_bytes));
  Status status = Protect(unprotected_bytes, protected_bytes);
  if (!status.ok()) {
    destroy_(protected_bytes);
    return {status, /*bytes=*/{}};
  }
  return {Status(), {protected_bytes}};
}

Status S2AFrameProtector::Protect(const std::vector<Iovec>& unprotected_bytes,
                                  Iovec& protected_bytes) {
  size_t bytes_remaining = GetTotalIovecLength(unprotected_bytes);
  bool unprotected_bytes_is_initially_empty = (bytes_remaining == 0);
  // |protected_bytes_index| is the index on |protected_bytes.iov_base| where
  // the start of the next TLS record should be written.
  size_t protected_bytes_index = 0;
  // |current_iovec_index| is the index on |unprotected_bytes|.
  size_t current_iovec_index = 0;
  // |on_iovec_index| is the index on |unprotected_bytes[current_iovec_index]|.
  size_t on_iovec_index = 0;

  absl::MutexLock lock(&protect_mu_);
  while (unprotected_bytes_is_initially_empty || bytes_remaining > 0) {
    if (unprotected_bytes_is_initially_empty) {
      unprotected_bytes_is_initially_empty = false;
    }
    size_t number_bytes_to_protect =
        bytes_remaining < kTls13MaxPlaintextBytesPerRecord
            ? bytes_remaining
            : kTls13MaxPlaintextBytesPerRecord;

    // Collect |Iovec|'s in |bytes_to_protect| that store the next
    // |number_bytes_to_protect| bytes from |unprotected_bytes|.
    std::vector<Iovec> bytes_to_protect;
    size_t bytes_to_protect_total_length = 0;
    while (bytes_to_protect_total_length < number_bytes_to_protect) {
      ABSL_ASSERT(current_iovec_index < unprotected_bytes.size());
      Iovec current_iovec = unprotected_bytes[current_iovec_index];
      size_t bytes_in_current_iovec_to_be_protected =
          std::min(current_iovec.iov_len - on_iovec_index,
                   number_bytes_to_protect - bytes_to_protect_total_length);
      bytes_to_protect.push_back(
          {static_cast<uint8_t*>(current_iovec.iov_base) + on_iovec_index,
           bytes_in_current_iovec_to_be_protected});

      on_iovec_index += bytes_in_current_iovec_to_be_protected;
      if (on_iovec_index >= current_iovec.iov_len) {
        current_iovec_index += 1;
        on_iovec_index = 0;
      }
      bytes_to_protect_total_length += bytes_in_current_iovec_to_be_protected;
    }

    // Protect the bytes in |bytes_to_protect| and write them to
    // |protected_bytes|. If a failure occurs or an unexpected number of bytes
    // are written, then free the |protected_bytes| buffer and return an error
    // status.
    S2ACrypterStatus status =
        crypter_->Protect(RecordType::APPLICATION_DATA, bytes_to_protect,
                          {static_cast<uint8_t*>(protected_bytes.iov_base) +
                               protected_bytes_index,
                           protected_bytes.iov_len - protected_bytes_index});
    if (status.GetCode() != S2ACrypterStatusCode::OK) {
      std::string error =
          absl::StrCat("Failed to protect: ", status.GetErrorMessage());
      logger_(error);
      destroy_(protected_bytes);
      return Status(ConvertStatusCode(status.GetCode()),
                    status.GetErrorMessage());
    }
    if (status.GetBytesWritten() !=
        number_bytes_to_protect + crypter_->RecordOverhead()) {
      std::string error = "Protected an unexpected number of bytes.";
      logger_(error);
      destroy_(protected_bytes);
      return Status(StatusCode::kInternal, error);
    }

    // Update the bytes remaining to protect.
    bytes_remaining -= number_bytes_to_protect;
    protected_bytes_index += status.GetBytesWritten();
  }
  return Status();
}

Status S2AFrameProtector::Unprotect(
    const std::vector<aead_crypter::Iovec>& protected_bytes,
    aead_crypter::Iovec& unprotected_bytes) {
  if (NumberBytesToUnprotect(protected_bytes) == 0) {
    return Status(StatusCode::kFailedPrecondition,
                  "|protected_bytes| is too small to contain a TLS record.");
  }

  // Compute the size of the TLS record held in |protected_bytes| and copy the
  // header into |header|.
  uint8_t header[kTls13RecordHeaderLength];
  absl::variant<Status, ComputeTlsRecordSizeResult> record_size_status =
      ComputeTlsRecordSize(protected_bytes, /*vec_index=*/0, /*on_vec_index=*/0,
                           header);
  switch (record_size_status.index()) {
    case 0:
      unprotected_bytes.iov_len = 0;
      logger_(absl::StrCat("Failed to compute TLS record size: ",
                           absl::get<0>(record_size_status).message()));
      return absl::get<0>(record_size_status);
    case 1:
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }
  ComputeTlsRecordSizeResult record_size_result =
      absl::get<1>(record_size_status);

  // Create a vector of Iovec's that consists only of the TLS payload.
  absl::variant<Status, IsolateTlsPayloadResult> isolate_status =
      IsolateTlsPayload(
          protected_bytes, record_size_result.iovec_index,
          record_size_result.on_vec_index,
          record_size_result.record_size - kTls13RecordHeaderLength);
  switch (isolate_status.index()) {
    case 0:
      unprotected_bytes.iov_len = 0;
      logger_(absl::StrCat("Failed to isolate TLS payload: ",
                           absl::get<0>(isolate_status).message()));
      return absl::get<0>(isolate_status);
    case 1:
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }

  S2ACrypterStatus status = crypter_->Unprotect(
      {header, kTls13RecordHeaderLength}, absl::get<1>(isolate_status).payload,
      unprotected_bytes);
  if (status.GetCode() != S2ACrypterStatusCode::OK) {
    unprotected_bytes.iov_len = 0;
    std::string error = "Failed to unprotect bytes from peer.";
    logger_(error);
    return Status(ConvertStatusCode(status.GetCode()),
                  status.GetErrorMessage());
  }
  unprotected_bytes.iov_len = status.GetBytesWritten();
  return Status();
}

Result S2AFrameProtector::Unprotect(const std::vector<Iovec>& protected_bytes) {
  size_t bytes_remaining = GetTotalIovecLength(protected_bytes);
  if (bytes_remaining < crypter_->RecordOverhead()) {
    return {Status(StatusCode::kFailedPrecondition,
                   "|protected_bytes| is too small to contain a TLS record."),
            /*bytes=*/{}};
  }

  // |current_iovec_index| is the index on |protected_bytes|.
  size_t current_iovec_index = 0;
  // |on_iovec_index| is the index on |protected_bytes[current_iovec_index]|.
  size_t on_iovec_index = 0;

  absl::MutexLock lock(&unprotect_mu_);
  std::vector<Iovec> plaintext;
  while (bytes_remaining >= crypter_->RecordOverhead()) {
    // Copy the header of the next TLS record in |protected_bytes| into
    // |header|, and update |current_iovec_index| and |on_iovec_index| so that
    // |protected_bytes[current_iovec_index].iov_base[on_iovec_index]| is the
    // first byte of the payload after the header.
    //
    // We require the header to be in a contiguous buffer because it is the AAD
    // for decrypting the record, and the AAD must be a contiguous buffer.
    uint8_t header[kTls13RecordHeaderLength];
    absl::variant<Status, ComputeTlsRecordSizeResult> record_size_status =
        ComputeTlsRecordSize(protected_bytes, current_iovec_index,
                             on_iovec_index, header);
    switch (record_size_status.index()) {
      case 0:
        logger_(absl::StrCat("Failed to compute TLS record size: ",
                             absl::get<0>(record_size_status).message()));
        return {absl::get<0>(record_size_status), /*bytes=*/{}};
      case 1:
        break;
      default:  // Unexpected variant case.
        ABSL_ASSERT(0);
    }
    ComputeTlsRecordSizeResult record_size_result =
        absl::get<1>(record_size_status);
    size_t payload_size =
        record_size_result.record_size - kTls13RecordHeaderLength;
    current_iovec_index = record_size_result.iovec_index;
    on_iovec_index = record_size_result.on_vec_index;

    // Create a vector of |Iovec|'s that contains exactly the TLS payload for
    // the TLS record, and update |current_iovec_index| and |on_iovec_index| so
    // that |protected_bytes[current_iovec_index].iov_base[on_iovec_index]| is
    // the first byte of the next TLS record.
    absl::variant<Status, IsolateTlsPayloadResult> isolate_status =
        IsolateTlsPayload(protected_bytes, current_iovec_index, on_iovec_index,
                          payload_size);
    switch (isolate_status.index()) {
      case 0:
        logger_(absl::StrCat("Failed to isolate TLS payload: ",
                             absl::get<0>(isolate_status).message()));
        return {absl::get<0>(isolate_status), /*bytes=*/{}};
      case 1:
        break;
      default:  // Unexpected variant case.
        ABSL_ASSERT(0);
    }
    IsolateTlsPayloadResult isolate_result = absl::get<1>(isolate_status);
    current_iovec_index = isolate_result.vec_index;
    on_iovec_index = isolate_result.on_vec_index;

    // Allocate a buffer that will hold the plaintext obtained from unprotecting
    // the TLS record. We must allocate |payload_size| bytes so that there is
    // room for the record type byte and tag, even though the plaintext will be
    // strictly smaller.
    Iovec unprotected_bytes = allocator_(payload_size);
    S2ACrypterStatus status =
        crypter_->Unprotect({header, kTls13RecordHeaderLength},
                            isolate_result.payload, unprotected_bytes);
    if (status.GetCode() != S2ACrypterStatusCode::OK) {
      std::string error = absl::StrFormat(
          "Failed to unprotect bytes from peer: %s", status.GetErrorMessage());
      logger_(error);
      destroy_(unprotected_bytes);
      for (auto& vec : plaintext) {
        destroy_(vec);
      }
      return {Status(ConvertStatusCode(status.GetCode()), error), /*bytes=*/{}};
    }
    unprotected_bytes.iov_len = status.GetBytesWritten();
    plaintext.push_back(unprotected_bytes);
    bytes_remaining -= kTls13RecordHeaderLength + payload_size;
  }
  return {Status(), plaintext};
}

size_t S2AFrameProtector::MaxRecordSize() const { return max_record_size_; }

size_t S2AFrameProtector::NumberBytesToProtect(
    const std::vector<Iovec>& unprotected_bytes) const {
  return NumberBytesToProtect(GetTotalIovecLength(unprotected_bytes));
}

size_t S2AFrameProtector::NumberBytesToProtect(
    size_t unprotected_bytes_length) const {
  // Determine the number of TLS records needed to hold |total_plaintext_length|
  // bytes of plaintext.
  size_t number_of_records =
      floor(unprotected_bytes_length / kTls13MaxPlaintextBytesPerRecord);
  if (unprotected_bytes_length == 0 ||
      number_of_records * kTls13MaxPlaintextBytesPerRecord !=
          unprotected_bytes_length) {
    number_of_records += 1;
  }
  return unprotected_bytes_length +
         number_of_records * crypter_->RecordOverhead();
}

size_t S2AFrameProtector::NumberBytesToUnprotect(
    const std::vector<aead_crypter::Iovec>& protected_bytes) const {
  return NumberBytesToUnprotect(GetTotalIovecLength(protected_bytes));
}

size_t S2AFrameProtector::NumberBytesToUnprotect(size_t record_length) const {
  if (record_length < crypter_->RecordOverhead()) {
    // The record is too small to hold 1 TLS record.
    return 0;
  }
  return record_length - kTls13RecordHeaderLength;
}

}  // namespace frame_protector
}  // namespace s2a
