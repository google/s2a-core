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

#include "handshaker/s2a_proxy.h"

#include <cstddef>
#include <iostream>

#include "handshaker/s2a_util.h"
#include "proto/common.upb.h"
#include "proto/s2a.upb.h"
#include "s2a_constants.h"
#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_proxy {

using ::absl::Status;
using ::absl::StatusCode;
using ::absl::StatusOr;
using ::s2a::frame_protector::S2AFrameProtector;
using ::s2a::s2a_context::S2AContext;
using ::s2a::s2a_options::S2AOptions;
using ::s2a::token_manager::AccessTokenManagerInterface;
using Buffer = S2AProxy::Buffer;
using ProxyStatus = S2AProxy::ProxyStatus;
using S2AProxyOptions = S2AProxy::S2AProxyOptions;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;
using S2AFrameProtectorOptions =
    ::s2a::frame_protector::S2AFrameProtector::S2AFrameProtectorOptions;

std::unique_ptr<S2AProxy> S2AProxy::Create(S2AProxyOptions& options) {
  if (options.logger == nullptr || options.options == nullptr) {
    return nullptr;
  }
  std::cout << "*********************In |S2AProxy::Create|, hs service url is " << options.options->handshaker_service_url() << std::endl;
  return absl::WrapUnique(new S2AProxy(
      options.logger, options.is_client, options.application_protocol,
      options.target_hostname, std::move(options.options),
      std::move(options.channel_factory), std::move(options.channel_options),
      std::move(options.token_manager)));
}

S2AProxy::S2AProxy(
    Logger logger, bool is_client, const std::string& application_protocol,
    const std::string& target_hostname, std::unique_ptr<S2AOptions> options,
    std::unique_ptr<s2a_channel::S2AChannelFactoryInterface> channel_factory,
    std::unique_ptr<
        s2a_channel::S2AChannelFactoryInterface::S2AChannelOptionsInterface>
        channel_options,
    std::unique_ptr<AccessTokenManagerInterface> token_manager)
    : logger_(logger),
      is_client_(is_client),
      application_protocol_(application_protocol),
      target_hostname_(target_hostname),
      options_(std::move(options)),
      channel_factory_(std::move(channel_factory)),
      channel_options_(std::move(channel_options)),
      token_manager_(std::move(token_manager)),
      selected_local_identity_(
          absl::UnknownError("No local identity has been selected.")) {
        if (options_ != nullptr) {
std::cout << "********************In |S2AProxy| constructor, hs service url is " << options_->handshaker_service_url() << std::endl;
          }
        }

// |PopulateTokenCache| is called each time the |S2AProxy| needs to create a
// |SessionReq| message to send to S2A. It populates |token_cache_| with tokens
// according to the following rules:
//
// 1. If |PopulateTokenCache| is called while preparing a
//    |ClientSessionStartReq| or a |ServerSessionStartReq| message, it fetch
//    tokens for every local identity in the set |options_->local_identities()|
//    and adds them to |token_cache_|. However, if the set
//    |options_->local_identities()| is empty, then it fetches a token for the
//    empty identity and adds it to |token_cache_|.
//
// 2. If |PopulateTokenCache| is called while preparing a |SessionNextReq|
//    message, it checks if |token_cache_| already contains a token for
//    |selected_local_identity_| and it returns if that is the case. Recall that
//    |selected_local_identity_| is the local identity specified by the S2A in
//    the |SessionResp| message that follows the |ClientSessionStartReq| or
//    |ServerSessionStartReq|. If |selected_local_identity_| is not populated
//    (because the S2A did not specify a local identity in the |SessionResp|),
//    then |token_cache_| will be populated by the same identities and tokens
//    from (1).
//
// The |S2AProxy| does not create |ResumptionTicketReq| messages.
//
// In the |GetClientStart()|, |GetServerStart()|, and |GetNext()| methods, the
// |S2AProxy| attaches one |AuthenticationMechanism| to the |SessionReq| message
// for each (key, value) pair in |token_cache_|. Note that the local identity of
// the |AuthenticationMechanism| is NOT set when the key is the empty identity;
// in this case, the S2A assumes that the token is associated with the default
// identity (which may not be known to the application).
void S2AProxy::PopulateTokenCache() {
  if (token_manager_ == nullptr) {
    logger_("No access token manager is registered with |S2AProxy|.");
    return;
  }
  // If the S2A has already returned a local identity, try to get a token for
  // this identity. If we can get a token for this identity, replace the token
  // cache with only this token.
  if (selected_local_identity_.ok()) {
    // If the token cache already consists of only 1 token for the selected
    // local identity, then there is nothing to do.
    if (token_cache_.contains(*selected_local_identity_) &&
        token_cache_.size() == 1) {
      return;
    }
    StatusOr<std::string> token =
        token_manager_->GetToken(*selected_local_identity_);
    if (token.ok()) {
      // If we can get a token for the selected local identity, clear the cache
      // and only add this token back to the cache.
      token_cache_.clear();
      token_cache_[*selected_local_identity_] = *token;
      return;
    }
    // If we can't get a token for the selected local identity, log this failure
    // and fallback to getting tokens for all local identities specified by
    // |options_|.
    logger_(absl::StrCat("Unable to retrieve access token: ",
                         token.status().message()));
  }

  // If the application did provide local identities, attempt to fetch a token
  // for each one.
  for (auto& local_identity : options_->local_identities()) {
    if (token_cache_.contains(local_identity)) {
      continue;
    }
    StatusOr<std::string> token = token_manager_->GetToken(local_identity);
    if (!token.ok()) {
      logger_(absl::StrCat("Unable to retrieve access token: ",
                           token.status().message()));
    } else {
      token_cache_[local_identity] = *token;
    }
  }

  // If the application did not provide any local identities, attempt to fetch a
  // token for the empty identity.
  if (options_->local_identities().empty()) {
    Identity empty_identity = Identity::GetEmptyIdentity();
    StatusOr<std::string> token = token_manager_->GetToken(empty_identity);
    if (!token.ok()) {
      logger_(absl::StrCat("Unable to retrieve access token: ",
                           token.status().message()));
    } else {
      token_cache_[empty_identity] = *token;
    }
  }
}

ProxyStatus S2AProxy::GetBytesForS2A(std::unique_ptr<Buffer> bytes_from_peer) {
  absl::MutexLock lock(&mu_);
  // If this is the first message to the S2A, prepare a client or server start
  // message.
  if (is_first_message_) {
    ProxyStatus status;
    if (is_client_) {
      if (bytes_from_peer != nullptr && !bytes_from_peer->empty()) {
        std::string error = "Handshake has not begun, not expecting bytes.";
        logger_(error);
        return {Status(StatusCode::kFailedPrecondition, error),
                /*bytes_consumed=*/0, /*buffer=*/nullptr};
      }
      status = GetClientStart();
    } else {
      status = GetServerStart(std::move(bytes_from_peer));
    }
    // If the client or server start was successfully created, then set
    // |is_first_message_| to false so that all future calls to |GetBytesForS2A|
    // yield a next message.
    if (status.status.ok()) {
      is_first_message_ = false;
    }
    return status;
  }
  if (bytes_from_peer == nullptr || bytes_from_peer->empty()) {
    std::string error = "Handshake requires bytes from peer.";
    logger_(error);
    return {Status(StatusCode::kFailedPrecondition, error),
            /*bytes_consumed=*/0, /*buffer=*/nullptr};
  }
  return GetNext(std::move(bytes_from_peer));
}

ProxyStatus S2AProxy::GetBytesForPeer(std::unique_ptr<Buffer> bytes_from_s2a) {
  absl::MutexLock lock(&mu_);
  if (bytes_from_s2a == nullptr || bytes_from_s2a->empty()) {
    std::string error = "Need bytes from S2A.";
    logger_(error);
    return {Status(StatusCode::kFailedPrecondition, error),
            /*bytes_consumed=*/0, /*buffer=*/nullptr};
  }

  // Deserialize the responsse from the S2A.
  upb::Arena arena;
  size_t buffer_len = bytes_from_s2a->size();
  void* arena_buffer = upb_arena_malloc(arena.ptr(), buffer_len);
  ABSL_ASSERT(arena_buffer != nullptr);
  memcpy(arena_buffer, bytes_from_s2a->data(), buffer_len);
  s2a_proto_SessionResp* response = s2a_proto_SessionResp_parse(
      reinterpret_cast<char*>(arena_buffer), buffer_len, arena.ptr());
  if (response == nullptr) {
    std::string error = "Deserializing response from the S2A failed.";
    logger_(error);
    return {Status(StatusCode::kInternal, error), /*bytes_consumed=*/0,
            /*buffer=*/nullptr};
  }

  // Check the status of the response from the S2A.
  const s2a_proto_SessionStatus* session_status =
      s2a_proto_SessionResp_status(response);
  if (session_status == nullptr ||
      s2a_proto_SessionStatus_code(session_status) != 0) {
    std::string error =
        session_status == nullptr
            ? ""
            : absl::StrCat(
                  "Error from the S2A: ",
                  ::s2a::s2a_util::ParseUpbStrview(
                      s2a_proto_SessionStatus_details(session_status)));
    logger_(error);
    return {Status(StatusCode::kInternal, error), /*bytes_consumed=*/0,
            /*buffer=*/nullptr};
  }

  // If S2A has already picked a local identity, replace the set
  // |local_identities_| with a singleton set containing only the local identity
  // picked by S2A. This stops us from fetching access tokens for local
  // identities that are not needed.
  if (s2a_proto_SessionResp_has_local_identity(response)) {
    selected_local_identity_ = {s2a_util::ConvertFromProtoToIdentity(
        s2a_proto_SessionResp_local_identity(response))};
  }

  if (s2a_proto_SessionResp_has_result(response)) {
    is_handshake_finished_ = true;
    const s2a_proto_SessionResult* result =
        s2a_proto_SessionResp_result(response);
    if (result == nullptr || !s2a_proto_SessionResult_has_state(result)) {
      std::string error = "|s2a_proto_SessionResult| is invalid.";
      logger_(error);
      return {Status(StatusCode::kInvalidArgument, error), /*bytes_consumed=*/0,
              /*buffer=*/nullptr};
    }
    const s2a_proto_SessionState* state = s2a_proto_SessionResult_state(result);
    result_ = absl::make_unique<S2AHandshakeResult>();

    // Parse and set the TLS version.
    absl::variant<Status, TlsVersion> tls_version_status =
        s2a_util::ConvertFromProtoToTlsVersion(
            static_cast<s2a_proto_TLSVersion>(
                s2a_proto_SessionState_tls_version(state)));
    switch (tls_version_status.index()) {
      case 0:
        logger_(absl::StrCat(
            "Error parsing TLS version from |s2a_proto_SessionResult|: ",
            absl::get<0>(tls_version_status).message()));
        return {absl::get<0>(tls_version_status), /*bytes_consumed=*/0,
                /*buffer=*/nullptr};
      case 1:
        break;
      default:  // Unexpected variant case.
        ABSL_ASSERT(0);
    }
    result_->tls_version = absl::get<1>(tls_version_status);

    // Parse and set the ciphersuite.
    absl::variant<Status, Ciphersuite> ciphersuite_status =
        s2a_util::ConvertFromProtoToCiphersuite(
            static_cast<s2a_proto_Ciphersuite>(
                s2a_proto_SessionState_tls_ciphersuite(state)));
    switch (ciphersuite_status.index()) {
      case 0:
        logger_(absl::StrCat(
            "Error parsing ciphersuite from |s2a_proto_SessionResult|: ",
            absl::get<0>(ciphersuite_status).message()));
        return {absl::get<0>(ciphersuite_status), /*bytes_consumed=*/0,
                /*buffer=*/nullptr};
      case 1:
        break;
      default:  // Unexpected variant case.
        ABSL_ASSERT(0);
    }
    result_->ciphersuite = absl::get<1>(ciphersuite_status);

    upb_strview in_traffic_secret = s2a_proto_SessionState_in_key(state);
    result_->in_traffic_secret = std::vector<uint8_t>(in_traffic_secret.size);
    memcpy(result_->in_traffic_secret.data(), in_traffic_secret.data,
           in_traffic_secret.size);

    upb_strview out_traffic_secret = s2a_proto_SessionState_out_key(state);
    result_->out_traffic_secret = std::vector<uint8_t>(out_traffic_secret.size);
    memcpy(result_->out_traffic_secret.data(), out_traffic_secret.data,
           out_traffic_secret.size);

    // |out_sequence| may be nonzero on server-side because, right after the
    // handshake is complete, one or more TLS records containing session tickets
    // may have been generated. This will increment |out_sequence| by the number
    // of TLS records generated.
    result_->in_sequence = s2a_proto_SessionState_in_sequence(state);
    result_->out_sequence = s2a_proto_SessionState_out_sequence(state);

    // TODO(matthewstevenson88): Enforce that peer identity is set.
    // TODO(matthewstevenson88) Check that peer identity appears in the list of
    // target identities; otherwise, fail.
    const s2a_proto_Identity* peer_identity =
        s2a_proto_SessionResult_peer_identity(result);
    if (peer_identity == nullptr) {
      logger_("No peer identity set in |s2a_proto_SessionResult|.");
    }

    const s2a_proto_Identity* local_identity =
        s2a_proto_SessionResult_local_identity(result);
    if (local_identity == nullptr) {
      std::string error = "No local identity set in |s2a_proto_SessionResult|.";
      logger_(error);
      return {Status(StatusCode::kInternal, error),
              /*bytes_consumed=*/0, /*buffer=*/nullptr};
    }
    result_->local_identity =
        s2a_util::ConvertFromProtoToIdentity(local_identity);
    result_->connection_id = s2a_proto_SessionState_connection_id(state);

    // Create the |S2AContext|.
    context_ = absl::make_unique<S2AContext>(
        s2a_util::ParseUpbStrview(
            s2a_proto_SessionResult_application_protocol(result)),
        absl::get<1>(tls_version_status), absl::get<1>(ciphersuite_status),
        s2a_util::ConvertFromProtoToIdentity(peer_identity),
        s2a_util::ConvertFromProtoToIdentity(local_identity),
        s2a_util::ParseUpbStrview(
            s2a_proto_SessionResult_peer_cert_fingerprint(result)),
        s2a_util::ParseUpbStrview(
            s2a_proto_SessionResult_local_cert_fingerprint(result)),
        s2a_proto_SessionState_is_handshake_resumed(state));
  }

  // Retrieve the |out_frames| to send to the peer.
  upb_strview out_frames = s2a_proto_SessionResp_out_frames(response);
  auto buffer = absl::make_unique<std::vector<char>>(out_frames.size);
  memcpy(buffer->data(), out_frames.data, out_frames.size);
  return {Status(), s2a_proto_SessionResp_bytes_consumed(response),
          std::move(buffer)};
}

ProxyStatus S2AProxy::GetClientStart() {
  upb::Arena arena;
  s2a_proto_SessionReq* request = s2a_proto_SessionReq_new(arena.ptr());
  s2a_proto_ClientSessionStartReq* client_start =
      s2a_proto_SessionReq_mutable_client_start(request, arena.ptr());

  // Set the application protocol.
  s2a_proto_ClientSessionStartReq_add_application_protocols(
      client_start, upb_strview_makez(application_protocol_.c_str()),
      arena.ptr());

  // Set the min and max TLS versions.
  absl::variant<Status, s2a_proto_TLSVersion> min_tls_version_status =
      ::s2a::s2a_util::ConvertTlsVersionToProto(options_->min_tls_version());
  switch (min_tls_version_status.index()) {
    case 0:
      logger_(std::string(absl::get<0>(min_tls_version_status).message()));
      return {absl::get<0>(min_tls_version_status), /*bytes_consumed=*/0,
              /*buffer=*/nullptr};
    case 1:
      s2a_proto_ClientSessionStartReq_set_min_tls_version(
          client_start, absl::get<1>(min_tls_version_status));
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }
  absl::variant<Status, s2a_proto_TLSVersion> max_tls_version_status =
      ::s2a::s2a_util::ConvertTlsVersionToProto(options_->max_tls_version());
  switch (max_tls_version_status.index()) {
    case 0:
      logger_(std::string(absl::get<0>(max_tls_version_status).message()));
      return {absl::get<0>(max_tls_version_status), /*bytes_consumed=*/0,
              /*buffer=*/nullptr};
    case 1:
      s2a_proto_ClientSessionStartReq_set_max_tls_version(
          client_start, absl::get<1>(max_tls_version_status));
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }

  // Set the list of supported TLS ciphersuites.
  int32_t* tls_ciphersuites =
      s2a_proto_ClientSessionStartReq_resize_tls_ciphersuites(
          client_start, options_->supported_ciphersuites().size(), arena.ptr());
  ABSL_ASSERT(tls_ciphersuites != nullptr);
  size_t index = 0;
  for (auto ciphersuite : options_->supported_ciphersuites()) {
    absl::variant<Status, s2a_proto_Ciphersuite> ciphersuite_status =
        ::s2a::s2a_util::ConvertCiphersuiteToProto(ciphersuite);
    switch (ciphersuite_status.index()) {
      case 0:
        logger_(std::string(absl::get<0>(ciphersuite_status).message()));
        return {absl::get<0>(ciphersuite_status), /*bytes_consumed=*/0,
                /*buffer=*/nullptr};
      case 1:
        tls_ciphersuites[index] = absl::get<1>(ciphersuite_status);
        index++;
        break;
      default:  // Unexpected variant case.
        ABSL_ASSERT(0);
    }
  }

  // Set the target identities.
  for (const auto& target_identity : options_->target_identities()) {
    s2a_proto_Identity* identity =
        s2a_proto_ClientSessionStartReq_add_target_identities(client_start,
                                                              arena.ptr());
    switch (target_identity.GetIdentityType()) {
      case IdentityType::SPIFFE_ID:
        s2a_proto_Identity_set_spiffe_id(
            identity, upb_strview_makez(target_identity.GetIdentityCString()));
        break;
      case IdentityType::HOSTNAME:
        s2a_proto_Identity_set_hostname(
            identity, upb_strview_makez(target_identity.GetIdentityCString()));
        break;
      default:
        std::string error = "Unsupported identity format.";
        logger_(error);
        return {Status(StatusCode::kFailedPrecondition, error),
                /*bytes_consumed=*/0, /*buffer=*/nullptr};
    }
  }

  // Set the local identity. The client should have at most 1 local identity. If
  // no local identity is provided, then the S2A will choose a default local
  // identity.
  if (options_->local_identities().size() > 1) {
    std::string error = "Client should have at most 1 local identity.";
    logger_(error);
    return {Status(StatusCode::kFailedPrecondition, error),
            /*bytes_consumed=*/0, /*buffer=*/nullptr};
  }
  if (options_->local_identities().size() == 1) {
    auto& local_identity = *options_->local_identities().begin();
    s2a_proto_Identity* identity =
        s2a_proto_ClientSessionStartReq_mutable_local_identity(client_start,
                                                               arena.ptr());
    switch (local_identity.GetIdentityType()) {
      case IdentityType::SPIFFE_ID:
        s2a_proto_Identity_set_spiffe_id(
            identity, upb_strview_makez(local_identity.GetIdentityCString()));
        break;
      case IdentityType::HOSTNAME:
        s2a_proto_Identity_set_hostname(
            identity, upb_strview_makez(local_identity.GetIdentityCString()));
        break;
      default:
        std::string error = "Unsupported identity format.";
        logger_(error);
        return {Status(StatusCode::kFailedPrecondition, error),
                /*bytes_consumed=*/0, /*buffer=*/nullptr};
    }
  }

  // Set the target name to the hostname of the server.
  s2a_proto_ClientSessionStartReq_set_target_name(
      client_start, upb_strview_makez(target_hostname_.c_str()));

  // Attach tokens per local identity, if a token manager exists.
  PopulateTokenCache();
  for (auto& pair : token_cache_) {
    s2a_proto_AuthenticationMechanism* auth_mechanism =
        s2a_proto_SessionReq_add_auth_mechanisms(request, arena.ptr());
    s2a_proto_AuthenticationMechanism_set_token(
        auth_mechanism, upb_strview_makez(pair.second.c_str()));
    s2a_proto_Identity* identity = nullptr;
    switch (pair.first.GetIdentityType()) {
      case s2a_options::S2AOptions::IdentityType::SPIFFE_ID:
        identity = s2a_proto_AuthenticationMechanism_mutable_identity(
            auth_mechanism, arena.ptr());
        s2a_proto_Identity_set_spiffe_id(
            identity, upb_strview_makez(pair.first.GetIdentityCString()));
        break;
      case s2a_options::S2AOptions::IdentityType::HOSTNAME:
        identity = s2a_proto_AuthenticationMechanism_mutable_identity(
            auth_mechanism, arena.ptr());
        s2a_proto_Identity_set_hostname(
            identity, upb_strview_makez(pair.first.GetIdentityCString()));
        break;
      default:
        logger_(
            absl::StrFormat("Encountered unknown identity type %d when trying "
                            "to attach access token.",
                            static_cast<int>(pair.first.GetIdentityType())));
        break;
    }
  }

  // Serialize the |ClientSessionStartReq| message.
  size_t buffer_len = 0;
  char* arena_buffer =
      s2a_proto_SessionReq_serialize(request, arena.ptr(), &buffer_len);
  if (arena_buffer == nullptr) {
    std::string error = "Error when serializing |ClientSessionStartReq|.";
    logger_(error);
    return {Status(StatusCode::kInternal, error), /*bytes_consumed=*/0,
            /*buffer=*/nullptr};
  }

  // Copy the serialized message to a buffer not tied to the arena.
  auto buffer = absl::make_unique<Buffer>(buffer_len);
  memcpy(buffer->data(), arena_buffer, buffer_len);
  return {Status(), /*bytes_consumed=*/0, std::move(buffer)};
}

ProxyStatus S2AProxy::GetServerStart(std::unique_ptr<Buffer> bytes_from_peer) {
  upb::Arena arena;
  s2a_proto_SessionReq* request = s2a_proto_SessionReq_new(arena.ptr());
  s2a_proto_ServerSessionStartReq* server_start =
      s2a_proto_SessionReq_mutable_server_start(request, arena.ptr());

  // Set the application protocol.
  s2a_proto_ServerSessionStartReq_add_application_protocols(
      server_start, upb_strview_makez(application_protocol_.c_str()),
      arena.ptr());

  // Set the min and max TLS versions.
  absl::variant<Status, s2a_proto_TLSVersion> min_tls_version_status =
      ::s2a::s2a_util::ConvertTlsVersionToProto(options_->min_tls_version());
  switch (min_tls_version_status.index()) {
    case 0:
      logger_(std::string(absl::get<0>(min_tls_version_status).message()));
      return {absl::get<0>(min_tls_version_status), /*bytes_consumed=*/0,
              /*buffer=*/nullptr};
    case 1:
      s2a_proto_ServerSessionStartReq_set_min_tls_version(
          server_start, absl::get<1>(min_tls_version_status));
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }
  absl::variant<Status, s2a_proto_TLSVersion> max_tls_version_status =
      ::s2a::s2a_util::ConvertTlsVersionToProto(options_->max_tls_version());
  switch (max_tls_version_status.index()) {
    case 0:
      logger_(std::string(absl::get<0>(max_tls_version_status).message()));
      return {absl::get<0>(max_tls_version_status), /*bytes_consumed=*/0,
              /*buffer=*/nullptr};
    case 1:
      s2a_proto_ServerSessionStartReq_set_max_tls_version(
          server_start, absl::get<1>(max_tls_version_status));
      break;
    default:  // Unexpected variant case.
      ABSL_ASSERT(0);
  }

  // Set the list of supported TLS ciphersuites.
  int32_t* tls_ciphersuites =
      s2a_proto_ServerSessionStartReq_resize_tls_ciphersuites(
          server_start, options_->supported_ciphersuites().size(), arena.ptr());
  ABSL_ASSERT(tls_ciphersuites != nullptr);
  size_t index = 0;
  for (auto ciphersuite : options_->supported_ciphersuites()) {
    absl::variant<Status, s2a_proto_Ciphersuite> ciphersuite_status =
        ::s2a::s2a_util::ConvertCiphersuiteToProto(ciphersuite);
    switch (ciphersuite_status.index()) {
      case 0:
        logger_(std::string(absl::get<0>(ciphersuite_status).message()));
        return {absl::get<0>(ciphersuite_status), /*bytes_consumed=*/0,
                /*buffer=*/nullptr};
      case 1:
        tls_ciphersuites[index] = absl::get<1>(ciphersuite_status);
        index++;
        break;
      default:  // Unexpected variant case.
        ABSL_ASSERT(0);
    }
  }

  // Adds the local identities supported by the server. If no local identities
  // are provided, then the S2A will choose a default a local identity.
  for (auto& local_identity : options_->local_identities()) {
    s2a_proto_Identity* identity =
        s2a_proto_ServerSessionStartReq_add_local_identities(server_start,
                                                             arena.ptr());
    switch (local_identity.GetIdentityType()) {
      case IdentityType::SPIFFE_ID:
        s2a_proto_Identity_set_spiffe_id(
            identity, upb_strview_makez(local_identity.GetIdentityCString()));
        break;
      case IdentityType::HOSTNAME:
        s2a_proto_Identity_set_hostname(
            identity, upb_strview_makez(local_identity.GetIdentityCString()));
        break;
      default:
        std::string error = "Unsupported identity format.";
        logger_(error);
        return {Status(StatusCode::kFailedPrecondition, error),
                /*bytes_consumed=*/0, /*buffer=*/nullptr};
    }
  }

  // Set the |in_bytes| received from the peer.
  if (bytes_from_peer != nullptr) {
    s2a_proto_ServerSessionStartReq_set_in_bytes(
        server_start,
        upb_strview_make(bytes_from_peer->data(), bytes_from_peer->size()));
  }

  // Attach tokens per local identity, if a token manager exists.
  PopulateTokenCache();
  for (const auto& pair : token_cache_) {
    s2a_proto_AuthenticationMechanism* auth_mechanism =
        s2a_proto_SessionReq_add_auth_mechanisms(request, arena.ptr());
    s2a_proto_AuthenticationMechanism_set_token(
        auth_mechanism, upb_strview_makez(pair.second.c_str()));
    s2a_proto_Identity* identity = nullptr;
    switch (pair.first.GetIdentityType()) {
      case s2a_options::S2AOptions::IdentityType::SPIFFE_ID:
        identity = s2a_proto_AuthenticationMechanism_mutable_identity(
            auth_mechanism, arena.ptr());
        s2a_proto_Identity_set_spiffe_id(
            identity, upb_strview_makez(pair.first.GetIdentityCString()));
        break;
      case s2a_options::S2AOptions::IdentityType::HOSTNAME:
        identity = s2a_proto_AuthenticationMechanism_mutable_identity(
            auth_mechanism, arena.ptr());
        s2a_proto_Identity_set_hostname(
            identity, upb_strview_makez(pair.first.GetIdentityCString()));
        break;
      default:
        logger_(
            absl::StrFormat("Encountered unknown identity type %d when trying "
                            "to attach access token.",
                            static_cast<int>(pair.first.GetIdentityType())));
        break;
    }
  }

  // Serialize the ServerSessionStartReq message.
  size_t buffer_len = 0;
  char* arena_buffer =
      s2a_proto_SessionReq_serialize(request, arena.ptr(), &buffer_len);
  if (arena_buffer == nullptr) {
    std::string error = "Error when serializing |ServerSessionStartReq|.";
    logger_(error);
    return {Status(StatusCode::kInternal, error), /*bytes_consumed=*/0,
            /*buffer=*/nullptr};
  }

  // Copy the serialized message to a buffer not tied to the arena.
  auto buffer = absl::make_unique<std::vector<char>>(buffer_len);
  memcpy(buffer->data(), arena_buffer, buffer_len);
  return {Status(), /*bytes_consumed=*/0, std::move(buffer)};
}

ProxyStatus S2AProxy::GetNext(std::unique_ptr<Buffer> bytes_from_peer) {
  upb::Arena arena;
  s2a_proto_SessionReq* request = s2a_proto_SessionReq_new(arena.ptr());
  s2a_proto_SessionNextReq* next =
      s2a_proto_SessionReq_mutable_next(request, arena.ptr());

  // Set the |in_bytes| received from the peer.
  if (bytes_from_peer != nullptr) {
    s2a_proto_SessionNextReq_set_in_bytes(
        next,
        upb_strview_make(bytes_from_peer->data(), bytes_from_peer->size()));
  }

  // Try to attach the token associated to the local identity selected by S2A in
  // the response to the client/server start request. If the S2A did not select
  // a local identity in the response, resend the auth mechanisms that were sent
  // in the client/server start request.
  PopulateTokenCache();
  for (const auto& pair : token_cache_) {
    s2a_proto_AuthenticationMechanism* auth_mechanism =
        s2a_proto_SessionReq_add_auth_mechanisms(request, arena.ptr());
    s2a_proto_AuthenticationMechanism_set_token(
        auth_mechanism, upb_strview_makez(pair.second.c_str()));
    s2a_proto_Identity* identity = nullptr;
    switch (pair.first.GetIdentityType()) {
      case s2a_options::S2AOptions::IdentityType::SPIFFE_ID:
        identity = s2a_proto_AuthenticationMechanism_mutable_identity(
            auth_mechanism, arena.ptr());
        s2a_proto_Identity_set_spiffe_id(
            identity, upb_strview_makez(pair.first.GetIdentityCString()));
        break;
      case s2a_options::S2AOptions::IdentityType::HOSTNAME:
        identity = s2a_proto_AuthenticationMechanism_mutable_identity(
            auth_mechanism, arena.ptr());
        s2a_proto_Identity_set_hostname(
            identity, upb_strview_makez(pair.first.GetIdentityCString()));
        break;
      default:
        logger_(
            absl::StrFormat("Encountered unknown identity type %d when trying "
                            "to attach access token.",
                            static_cast<int>(pair.first.GetIdentityType())));
        break;
    }
  }

  // Serialize the ServerSessionStartReq message.
  size_t buffer_len = 0;
  char* arena_buffer =
      s2a_proto_SessionReq_serialize(request, arena.ptr(), &buffer_len);
  if (arena_buffer == nullptr) {
    std::string error = "Error when serializing |SessionNextReq|.";
    logger_(error);
    return {Status(StatusCode::kInternal, error), /*bytes_consumed=*/0,
            /*buffer=*/nullptr};
  }

  // Copy the serialized message to a buffer not tied to the arena.
  auto buffer = absl::make_unique<std::vector<char>>(buffer_len);
  memcpy(buffer->data(), arena_buffer, buffer_len);
  return {Status(), /*bytes_consumed=*/0, std::move(buffer)};
}

bool S2AProxy::IsHandshakeFinished() {
  absl::MutexLock lock(&mu_);
  return is_handshake_finished_;
}

namespace {

aead_crypter::Iovec Allocator(size_t length) {
  return {new uint8_t[length], length};
}

void Destroy(aead_crypter::Iovec iovec) {
  delete[] static_cast<uint8_t*>(iovec.iov_base);
}

}  // namespace

absl::StatusOr<std::unique_ptr<S2AFrameProtector>>
S2AProxy::CreateFrameProtector() {
  if (!IsHandshakeFinished()) {
    logger_("Handshake is not finished.");
    return Status(StatusCode::kFailedPrecondition,
                  "Handshake is not finished.");
  }
  if (options_ != nullptr) {
    std::cout << "************In CreateFrameProtector, hs url is " << options_->handshaker_service_url() << std::endl;
  }
  S2AFrameProtectorOptions options = {result_->tls_version,
                                      result_->ciphersuite,
                                      result_->in_traffic_secret,
                                      result_->out_traffic_secret,
                                      result_->in_sequence,
                                      result_->out_sequence,
                                      std::string(options_->handshaker_service_url()),
                                      result_->local_identity,
                                      result_->connection_id,
                                      std::move(channel_factory_),
                                      std::move(channel_options_),
                                      Allocator,
                                      Destroy,
                                      logger_};
  return S2AFrameProtector::Create(options);
}

absl::variant<Status, std::unique_ptr<S2AContext>> S2AProxy::GetS2AContext() {
  if (!IsHandshakeFinished()) {
    logger_("Handshake is not finished.");
    return Status(StatusCode::kFailedPrecondition,
                  "Handshake is not finished.");
  }
  return std::move(context_);
}

}  // namespace s2a_proxy
}  // namespace s2a
