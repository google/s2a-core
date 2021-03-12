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

#include "record_protocol/s2a_crypter.h"

#include <cstddef>
#include <memory>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_format.h"
#include "crypto/hkdf.h"
#include "crypto/s2a_aead_crypter.h"
#include "record_protocol/s2a_crypter_util.h"
#include "s2a_constants.h"

namespace s2a {

using ::absl::Status;
using ::absl::StatusCode;
using ::s2a::aead_crypter::Iovec;
using ::s2a::aead_crypter::S2AAeadCrypter;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;
using CrypterStatus = ::s2a::aead_crypter::S2AAeadCrypter::CrypterStatus;
using RecordType = ::s2a::record_protocol::S2ACrypter::RecordType;
using S2ACrypterStatus = ::s2a::record_protocol::S2ACrypter::S2ACrypterStatus;
using S2ACrypterStatusCode =
    ::s2a::record_protocol::S2ACrypter::S2ACrypterStatusCode;
using handshake_message_handler::HandshakeMessageHandler;
using handshake_message_handler::kMaxNumTicketsToProcess;
using HandshakeMessageHandlerResult =
    handshake_message_handler::HandshakeMessageHandler::Result;
using MessageFragment = std::vector<uint8_t>;
using Message = std::vector<std::unique_ptr<MessageFragment>>;

namespace record_protocol {
namespace {

constexpr uint8_t kTls12ApplicationData = 0x17;
constexpr uint8_t kTls12WireVersion = 0x03;
constexpr size_t kTls13HeaderLength = 5;
constexpr size_t kTls13MaxPlaintextBytesPerRecord = 16384;  // 2^14

// The TLS 1.3 record types. See https://tools.ietf.org/html/rfc8446#section-5.1
// for the numerical values of the TLS record types.
constexpr uint8_t kTls13Alert = 0x15;
constexpr uint8_t kTls13ApplicationData = 0x17;
constexpr uint8_t kTls13Handshake = 0x16;
constexpr uint8_t kTlsAlertCloseNotify = 0x00;

absl::variant<Status, uint8_t> ConvertRecordType(RecordType record_type) {
  switch (record_type) {
    case RecordType::APPLICATION_DATA:
      return kTls13ApplicationData;
    case RecordType::ALERT:
      return kTls13Alert;
    case RecordType::HANDSHAKE:
      return kTls13Handshake;
    default:
      return Status(StatusCode::kFailedPrecondition,
                    "Unrecognized record type.");
  }
}

S2ACrypterStatusCode ConvertStatusCode(StatusCode code) {
  switch (code) {
    case StatusCode::kOk:
      return S2ACrypterStatusCode::OK;
    case StatusCode::kUnknown:
      return S2ACrypterStatusCode::UNKNOWN;
    case StatusCode::kInvalidArgument:
      return S2ACrypterStatusCode::INVALID_ARGUMENT;
    case StatusCode::kFailedPrecondition:
      return S2ACrypterStatusCode::FAILED_PRECONDITION;
    case StatusCode::kUnimplemented:
      return S2ACrypterStatusCode::UNIMPLEMENTED;
    default:
      return S2ACrypterStatusCode::INTERNAL_ERROR;
  }
}

size_t GetTotalIovecLength(const std::vector<Iovec>& vec) {
  size_t total_length = 0;
  for (auto& iovec : vec) {
    total_length += iovec.iov_len;
  }
  return total_length;
}

void ZeroOutIovec(const Iovec& iovec) {
  uint8_t* ptr = static_cast<uint8_t*>(iovec.iov_base);
  for (size_t i = 0; i < iovec.iov_len; i++) {
    ptr[i] = 0x00;
  }
}

Status WriteTls13RecordHeader(Iovec header, size_t payload_size) {
  if (header.iov_base == nullptr || header.iov_len != kTls13HeaderLength) {
    return Status(StatusCode::kInvalidArgument,
                  "Argument |header| to |WriteTls13RecordHeader| is invalid.");
  }
  uint8_t* header_ptr = static_cast<uint8_t*>(header.iov_base);
  header_ptr[0] = kTls12ApplicationData;
  header_ptr[1] = kTls12WireVersion;
  header_ptr[2] = kTls12WireVersion;
  header_ptr[3] = payload_size >> 8;
  header_ptr[4] = payload_size & 0xff;
  return Status();
}

// Validates the record header stored in |header| of a TLS 1.3 record with total
// length equal to |record_size|.
bool ValidateTls13RecordHeader(const Iovec& header, size_t record_size) {
  if (header.iov_base == nullptr || header.iov_len != kTls13HeaderLength) {
    return false;
  }
  uint8_t* header_ptr = reinterpret_cast<uint8_t*>(header.iov_base);
  if (header_ptr[0] != kTls12ApplicationData ||
      header_ptr[1] != kTls12WireVersion ||
      header_ptr[2] != kTls12WireVersion) {
    return false;
  }
  size_t first_payload_component = static_cast<int>(header_ptr[3] & 0xff) << 8;
  size_t second_payload_component = static_cast<int>(header_ptr[4] & 0xff);
  return (record_size == kTls13HeaderLength + first_payload_component +
                             second_payload_component);
}

}  // namespace

S2ACrypterStatus::S2ACrypterStatus(S2ACrypterStatusCode code,
                                   const std::string& error_message,
                                   size_t bytes_written)
    : code_(code),
      error_message_(error_message),
      bytes_written_(bytes_written) {}

S2ACrypterStatusCode S2ACrypterStatus::GetCode() const { return code_; }

std::string S2ACrypterStatus::GetErrorMessage() const { return error_message_; }

size_t S2ACrypterStatus::GetBytesWritten() const { return bytes_written_; }

S2ACrypter::S2ACrypter(
    const uint64_t connection_id, const std::string& handshaker_service_url,
    const s2a_options::S2AOptions::Identity local_identity,
    std::unique_ptr<record_protocol::S2AHalfConnection> in_connection,
    std::unique_ptr<record_protocol::S2AHalfConnection> out_connection,
    s2a_ticket_sender::TicketSender ticket_sender_function,
    std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory,
    std::unique_ptr<
        s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
        channel_options,
    std::function<void(const std::string&)> logger)
    : connection_id_(connection_id),
      handshaker_service_url_(handshaker_service_url),
      local_identity_(local_identity),
      logger_(logger),
      in_connection_(std::move(in_connection)),
      out_connection_(std::move(out_connection)),
      handshake_message_handler_(absl::make_unique<HandshakeMessageHandler>()),
      hs_message_handling_state_(
          absl::make_unique<HandshakeMessageHandlingState>()),
      channel_factory_(std::move(channel_factory)),
      channel_options_(std::move(channel_options)),
      ticket_sender_function_(ticket_sender_function) {}

S2ACrypter::~S2ACrypter() {
  if (wait_on_ticket_sender_function_ != nullptr) {
    if (!wait_on_ticket_sender_function_()) {
      logger_("Ticket sending request finished with an error.");
    }
  }
}

absl::variant<Status, std::unique_ptr<S2ACrypter>> S2ACrypter::Create(
    TlsVersion tls_version, Ciphersuite ciphersuite, uint64_t connection_id,
    const std::string& handshaker_service_url,
    const s2a_options::S2AOptions::Identity local_identity,
    const std::vector<uint8_t>& in_traffic_secret,
    const std::vector<uint8_t>& out_traffic_secret, uint64_t in_sequence,
    uint64_t out_sequence,
    s2a_ticket_sender::TicketSender ticket_sender_function,
    std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory,
    std::unique_ptr<
        s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
        channel_options,
    std::function<void(const std::string&)> logger) {
  // Input checks.
  if (handshaker_service_url.empty()) {
    return Status(StatusCode::kInvalidArgument,
                  "|handshaker_service_url| is empty.");
  }
  if (logger == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "|logger| must not be nullptr.");
  }
  if (ticket_sender_function == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "|ticket_sender_function| must not be nullptr.");
  }
  if (tls_version != TlsVersion::TLS1_3) {
    return Status(StatusCode::kInvalidArgument,
                  "TLS 1.3 is the only supported TLS version.");
  }

  // Create the inbound half connection.
  absl::variant<Status, std::unique_ptr<S2AHalfConnection>> in_status =
      S2AHalfConnection::Create(ciphersuite, in_sequence, in_traffic_secret);
  std::unique_ptr<S2AHalfConnection> in_connection = nullptr;
  switch (in_status.index()) {
    case 0:
      return absl::get<0>(in_status);
    case 1:
      in_connection = std::move(absl::get<1>(in_status));
      break;
    default:  // This code should not be reached.
      ABSL_ASSERT(0);
  }

  // Create the outbound half connection.
  absl::variant<Status, std::unique_ptr<S2AHalfConnection>> out_status =
      S2AHalfConnection::Create(ciphersuite, out_sequence, out_traffic_secret);
  std::unique_ptr<S2AHalfConnection> out_connection = nullptr;
  switch (out_status.index()) {
    case 0:
      return absl::get<0>(out_status);
    case 1:
      out_connection = std::move(absl::get<1>(out_status));
      break;
    default:  // This code should not be reached.
      ABSL_ASSERT(0);
  }

  return absl::WrapUnique(
      new S2ACrypter(connection_id, handshaker_service_url, local_identity,
                     std::move(in_connection), std::move(out_connection),
                     ticket_sender_function, std::move(channel_factory),
                     std::move(channel_options), logger));
}

S2ACrypterStatus S2ACrypter::Protect(RecordType record_type,
                                     const std::vector<Iovec>& plaintext,
                                     const Iovec& record) {
  // Check that the length of |plaintext| does not exceed the maximum allowed
  // number of plaintext bytes per TLS 1.3 record.
  size_t plaintext_length = GetTotalIovecLength(plaintext);
  if (plaintext_length > kTls13MaxPlaintextBytesPerRecord) {
    std::string error =
        "|plaintext| contains more bytes than are allowed in a "
        "single TLS 1.3 record.";
    logger_(error);
    return {S2ACrypterStatusCode::FAILED_PRECONDITION, error,
            /*bytes_written=*/0};
  }
  // Check that |record| is large enough to hold the TLS 1.3 record formed from
  // |plaintext|.
  if (record.iov_len < plaintext_length + RecordOverhead()) {
    std::string error =
        "|record| is not large enough to hold the TLS 1.3 record "
        "built from |plaintext|.";
    logger_(error);
    return {S2ACrypterStatusCode::FAILED_PRECONDITION, error,
            /*bytes_written=*/0};
  }

  // Write the TLS 1.3 record header to the start of |record|.
  size_t payload_size =
      plaintext_length + /*record_type=*/1 + out_connection_->TagLength();
  uint8_t* record_header_ptr = static_cast<uint8_t*>(record.iov_base);
  ABSL_ASSERT(record_header_ptr != nullptr);
  Status header_status = WriteTls13RecordHeader(
      {record_header_ptr, kTls13HeaderLength}, payload_size);
  if (!header_status.ok()) {
    logger_("Unable to write TLS record header.");
    return {ConvertStatusCode(header_status.code()),
            std::string(header_status.message()), /*bytes_written=*/0};
  }

  // Collect the plaintext and the record type byte into one vector.
  absl::variant<Status, uint8_t> record_type_status =
      ConvertRecordType(record_type);
  if (record_type_status.index() != 1) {
    ABSL_ASSERT(record_type_status.index() == 0);
    logger_("Unable to parse TLS record type.");
    return {ConvertStatusCode(absl::get<0>(record_type_status).code()),
            std::string(absl::get<0>(record_type_status).message()),
            /*bytes_written=*/0};
  }
  uint8_t record_type_byte = absl::get<1>(record_type_status);
  Iovec record_type_vec = {&record_type_byte, 1};
  std::vector<Iovec> unprotected_payload(plaintext.size() + 1);
  for (size_t i = 0; i < plaintext.size(); i++) {
    unprotected_payload[i] = plaintext[i];
  }
  unprotected_payload[plaintext.size()] = record_type_vec;

  // Encrypt the plaintext and record type byte, and write the tag. The aad is
  // the TLS 1.3 record header.
  Iovec aad = {record_header_ptr, kTls13HeaderLength};
  CrypterStatus encrypt_status = out_connection_->Encrypt(
      {aad}, unprotected_payload,
      {static_cast<uint8_t*>(record.iov_base) + kTls13HeaderLength,
       record.iov_len - kTls13HeaderLength});
  if (!encrypt_status.GetStatus().ok()) {
    logger_(absl::StrFormat("Encryption failure: %s",
                            encrypt_status.GetStatus().message()));
    ZeroOutIovec(record);
    return {ConvertStatusCode(encrypt_status.GetStatus().code()),
            std::string(encrypt_status.GetStatus().message()),
            /*bytes_written=*/0};
  }
  return {S2ACrypterStatusCode::OK, /*error_message=*/"",
          encrypt_status.GetBytesWritten() + kTls13HeaderLength};
}

S2ACrypterStatus S2ACrypter::Unprotect(const Iovec& header,
                                       const std::vector<Iovec>& payload,
                                       const Iovec& plaintext) {
  if (close_notify_received_) {
    std::string error =
        "Close notify alert has been received. Close the connection.";
    logger_(error);
    return {S2ACrypterStatusCode::ALERT_CLOSE_NOTIFY, error,
            /*bytes_written=*/0};
  }

  // Check that |header| and |payload| is large enough to hold a TLS 1.3 record.
  size_t record_length = header.iov_len + GetTotalIovecLength(payload);
  if (record_length < RecordOverhead()) {
    std::string error = "Did not receive a complete TLS 1.3 record.";
    logger_(error);
    return {S2ACrypterStatusCode::FAILED_PRECONDITION, error,
            /*bytes_written=*/0};
  }

  // Check that |record| does not exceed the max allowed size. If it does, must
  // send a "record overflow" alert and the connection must be terminated; see
  // https://tools.ietf.org/html/rfc8446#section-5.2.
  if (record_length > RecordOverhead() + kTls13MaxPlaintextBytesPerRecord) {
    std::string error = "TLS 1.3 record contains more bytes than allowed.";
    logger_(error);
    return {S2ACrypterStatusCode::ALERT_RECORD_OVERFLOW, error,
            /*bytes_written=*/0};
  }

  // Validate the TLS record header.
  if (!ValidateTls13RecordHeader(header, record_length)) {
    std::string error = "TLS 1.3 record header is invalid.";
    logger_(error);
    return {S2ACrypterStatusCode::FAILED_PRECONDITION, error,
            /*bytes_written=*/0};
  }

  CrypterStatus decrypt_status =
      in_connection_->Decrypt({header}, payload, plaintext);
  if (!decrypt_status.GetStatus().ok()) {
    std::string error = absl::StrFormat("Decryption failed: %s",
                                        decrypt_status.GetStatus().message());
    logger_(error);
    ZeroOutIovec(plaintext);
    return {S2ACrypterStatusCode::INTERNAL_ERROR, error, /*bytes_written=*/0};
  }

  uint8_t* plaintext_ptr = reinterpret_cast<uint8_t*>(plaintext.iov_base);
  ABSL_ASSERT(plaintext_ptr != nullptr);
  /** At this point, the |s2a_decrypt_payload| method has written
   *  |*plaintext_bytes_written| bytes to |plaintext|, and these bytes are of
   *  the form (plaintext) + (record type byte) + (trailing zeros). These
   *  trailing zeros should be ignored, so we will search from one end of the
   *  |plaintext| buffer until we find the first nonzero trailing byte, which
   *  must be the record type.
   *
   *  Note that this TLS 1.3 implementation does not add padding by zeros when
   *  constructing a TLS 1.3 record; nonetheless, |s2a_decrypt_payload| must
   *  be able to parse a TLS 1.3 record that does have padding by zeros. **/
  size_t i;
  for (i = decrypt_status.GetBytesWritten() - 1;
       i < decrypt_status.GetBytesWritten(); i--) {
    if (plaintext_ptr[i] != 0) {
      break;
    }
  }
  if (i >= decrypt_status.GetBytesWritten()) {
    std::string error = "TLS 1.3 record does not have record type byte.";
    logger_(error);
    return {S2ACrypterStatusCode::INVALID_RECORD, error, /*bytes_written=*/0};
  }
  uint8_t record_type = plaintext_ptr[i];
  /** The plaintext only occupies the first i bytes of the |plaintext| buffer,
   *  so |plaintext_bytes_written| must be updated accordingly. **/
  size_t bytes_written = i;

  absl::variant<absl::Status, HandshakeMessageHandlerResult> result;
  absl::Status process_result_status;
  switch (record_type) {
    case kTls13Alert:
      if (bytes_written < 2) {
        std::string error = "The TLS 1.3 alert record is too small.";
        logger_(error);
        ZeroOutIovec(plaintext);
        return {S2ACrypterStatusCode::INVALID_RECORD, error,
                /*bytes_written=*/0};
      }
      if (plaintext_ptr[1] == kTlsAlertCloseNotify) {
        std::string error = "Received close notify alert.";
        logger_(error);
        close_notify_received_ = true;
        ZeroOutIovec(plaintext);
        return {S2ACrypterStatusCode::ALERT_CLOSE_NOTIFY, error,
                /*bytes_written=*/0};
      } else {
        // TODO(matthewstevenson88): add finer parsing of other alert types.
        std::string error =
            absl::StrFormat("Received alert of type %d.", record_type);
        logger_(error);
        ZeroOutIovec(plaintext);
        return {S2ACrypterStatusCode::ALERT_OTHER, error, /*bytes_written=*/0};
      }
    case kTls13Handshake:
      result = handshake_message_handler_->ProcessHandshakeMessage(
          plaintext_ptr, bytes_written);
      process_result_status = HandleProcessHandshakeMessageResult(result);
      if (!process_result_status.ok()) {
        std::string error =
            absl::StrFormat("Failed to process handshake message result: %s",
                            process_result_status.message());
        logger_(error);
        return {S2ACrypterStatusCode::INTERNAL_ERROR, error,
                /*bytes_written=*/0};
      }
      // The number of bytes written is set to zero in the output so that the
      // caller does not interpret the ticket as application data.
      return {S2ACrypterStatusCode::OK, /*error_message=*/"",
              /*bytes_written=*/0};
    case kTls13ApplicationData:
      // It is a protocol error if application data is received while expecting
      // to read more handshake bytes.
      if (hs_message_handling_state_->expecting_to_read_more_bytes) {
        std::string error =
            "Received a non handshake message while expecting a handshake "
            "message.";
        logger_(error);
        return {S2ACrypterStatusCode::INVALID_RECORD, error,
                /*bytes_written=*/0};
      }
      if (hs_message_handling_state_->phase == TicketHandlingPhase::RECEIVING) {
        RetrieveStoredTicketsAndSendToS2A();
        hs_message_handling_state_->phase = TicketHandlingPhase::DONE;
      }
      // There is nothing more to be done for an application data record.
      break;
    default:
      std::string error =
          absl::StrFormat("TLS record type byte %d is invalid.", record_type);
      logger_(error);
      ZeroOutIovec(plaintext);
      return {S2ACrypterStatusCode::INVALID_RECORD, error, /*bytes_written=*/0};
  }
  return {S2ACrypterStatusCode::OK, /*error_message=*/"", bytes_written};
}

size_t S2ACrypter::RecordOverhead() const {
  // The tag lengths of |in_connection_| and |out_connection_| must coincide.
  return kTls13HeaderLength + /*record_type=*/1 + in_connection_->TagLength();
}

Status S2ACrypter::UpdateOutboundKey() { return out_connection_->UpdateKey(); }

absl::Status S2ACrypter::HandleProcessHandshakeMessageResult(
    absl::variant<absl::Status, HandshakeMessageHandlerResult>
        result_or_status) {
  HandshakeMessageHandler::Result result;
  switch (result_or_status.index()) {
    case 0:
      return absl::get<0>(result_or_status);
    case 1:
      result = absl::get<1>(result_or_status);
      hs_message_handling_state_->expecting_to_read_more_bytes =
          result.expecting_to_read_more_bytes;

      // Update the inbound key if handshake message contained a key update
      // message.
      if (result.contains_key_update) {
        // TODO(matthewstevenson88): If |result.key_update_type == 0x01|, then
        // the peer is expecting a key update to be sent from us. See
        // https://tools.ietf.org/html/rfc8446#section-4.6.3.
        if (!in_connection_->UpdateKey().ok()) {
          logger_("Key update failed.");
          return absl::Status(absl::StatusCode::kInternal,
                              "Key update failed.");
        }
      }
      // Check if handshake message contained a ticket.
      switch (hs_message_handling_state_->phase) {
        case TicketHandlingPhase::NOT_RECEIVED:
          if (result.contains_ticket) {
            // The first ticket message was processed.
            hs_message_handling_state_->phase = TicketHandlingPhase::RECEIVING;
          }
          ABSL_FALLTHROUGH_INTENDED;
        case TicketHandlingPhase::RECEIVING:
          // If the limit of number of tickets to process is reached, send all
          // stored tickets to the S2A.
          if (result.contains_ticket &&
              result.num_full_tickets_stored >= kMaxNumTicketsToProcess) {
            RetrieveStoredTicketsAndSendToS2A();
            hs_message_handling_state_->expecting_to_read_more_bytes = false;
            hs_message_handling_state_->phase = TicketHandlingPhase::DONE;
            return absl::Status();
          }
          break;
        case TicketHandlingPhase::DONE:
          // Tickets received in this state are ignored.
          if (result.contains_ticket) {
            logger_(
                "Received a session ticket from the peer. It is being "
                "ignored.");
          }
          return absl::Status();
        default:
          return absl::Status(absl::StatusCode::kInternal,
                              "Unexpected ticket handling phase.");
      }
      return absl::Status();
    default:  // This code should not be reached.
      return absl::Status(absl::StatusCode::kInternal, "Unreachable.");
  }
}

void S2ACrypter::RetrieveStoredTicketsAndSendToS2A() {
  ABSL_ASSERT(ticket_sender_function_ != nullptr);

  // Retrieve stored ticket fragments, and merge the fragments when possible.
  // TODO(matthewstevenson88): Consider directly writing the fragments to the
  // proto message
  absl::variant<absl::Status,
                std::unique_ptr<std::vector<std::unique_ptr<Message>>>>
      ticket_fragments_status = handshake_message_handler_->GetStoredTickets();

  auto tickets = absl::make_unique<std::vector<std::unique_ptr<std::string>>>();
  switch (ticket_fragments_status.index()) {
    case 0:
      logger_(absl::StrFormat("Retrieving tickets failed: %s",
                              absl::get<0>(ticket_fragments_status).message()));
      return;
    case 1:
      for (auto& ticket : *(absl::get<1>(ticket_fragments_status))) {
        size_t ticket_total_size = 0;
        for (auto& fragment : *ticket) {
          ticket_total_size += fragment->size();
        }
        // Merge ticket fragments.
        auto full_ticket = absl::make_unique<std::string>(ticket_total_size, 0);
        size_t at_byte = 0;
        for (auto& fragment : *ticket) {
          memcpy(const_cast<char*>(full_ticket->data()) + at_byte,
                 fragment->data(), fragment->size());
          at_byte += fragment->size();
        }
        tickets->push_back(std::move(full_ticket));
      }
      break;
    default:  // This code should not be reached.
      ABSL_ASSERT(0);
  }
  s2a_ticket_sender::TicketSenderOptions ticket_sender_options = {
      handshaker_service_url_,
      connection_id_,
      local_identity_,
      std::move(tickets),
      std::move(channel_factory_),
      std::move(channel_options_)};
  wait_on_ticket_sender_function_ =
      ticket_sender_function_(ticket_sender_options);
}

}  // namespace record_protocol
}  // namespace s2a
