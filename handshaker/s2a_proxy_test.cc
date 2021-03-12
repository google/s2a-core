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

#include <iostream>

#include "absl/status/status.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "handshaker/s2a_context.h"
#include "proto/common.upb.h"
#include "proto/s2a.upb.h"
#include "s2a_constants.h"
#include "token_manager/fake_access_token_manager.h"
#include "upb/upb.hpp"

namespace s2a {
namespace s2a_proxy {
namespace {

using ::absl::Status;
using ::absl::StatusCode;
using ::s2a::s2a_context::S2AContext;
using ::s2a::s2a_options::S2AOptions;
using ::s2a::token_manager::testing::FakeAccessTokenManager;
using Buffer = ::s2a::s2a_proxy::S2AProxy::Buffer;
using ProxyStatus = ::s2a::s2a_proxy::S2AProxy::ProxyStatus;
using S2AProxyOptions = ::s2a::s2a_proxy::S2AProxy::S2AProxyOptions;
using Ciphersuite = ::s2a::s2a_options::S2AOptions::Ciphersuite;
using Identity = ::s2a::s2a_options::S2AOptions::Identity;
using IdentityType = ::s2a::s2a_options::S2AOptions::IdentityType;
using TlsVersion = ::s2a::s2a_options::S2AOptions::TlsVersion;

constexpr size_t kAes128GcmTrafficSecretSize = 32;
constexpr char kApplicationProtocol[] = "application_protocol";
constexpr char kClientLocalSpiffeId[] = "client_local_spiffe_id";
constexpr char kClientLocalHostname[] = "client_local_hostname";
constexpr char kClientTargetHostname[] = "target_hostname";
constexpr char kClientTargetSpiffeId[] = "target_spiffe_id";
constexpr size_t kConnectionId = 1234;
constexpr char kHandshakerServiceAddress[] = "handshaker_service_address";
constexpr char kHostname[] = "hostname";
constexpr char kInBytes[] = "in_bytes";
constexpr size_t kInBytesLength = 8;
constexpr bool kIsHandshakeResumed = false;
constexpr char kLocalCertFingerprint[] = "local_cert_fingerprint";
constexpr char kOutBytes[] = "out_bytes";
constexpr size_t kOutBytesLength = 9;
constexpr char kPeerCertFingerprint[] = "peer_cert_fingerprint";
constexpr char kResponseErrorMessage[] = "response_error_message";
constexpr char kServerLocalSpiffeId[] = "server_local_spiffe_id";
constexpr char kServerLocalHostname[] = "server_local_hostname";

bool was_message_logged = false;
void FakeLogger(const std::string& message) {
  was_message_logged = true;
  std::cerr << "FakeLogger: " << message << std::endl;
}

std::unique_ptr<S2AOptions> CreateTestOptions(
    bool is_client, bool unsupported_ciphersuite,
    bool client_multiple_local_identities, bool with_local_identities) {
  auto options = absl::make_unique<S2AOptions>();
  options->set_handshaker_service_url(kHandshakerServiceAddress);
  options->add_supported_ciphersuite(Ciphersuite::AES_128_GCM_SHA256);
  options->add_supported_ciphersuite(Ciphersuite::AES_256_GCM_SHA384);
  options->add_supported_ciphersuite(Ciphersuite::CHACHA20_POLY1305_SHA256);
  if (unsupported_ciphersuite) {
    options->add_supported_ciphersuite(static_cast<Ciphersuite>(4));
  }
  if (is_client) {
    options->add_target_spiffe_id(kClientTargetSpiffeId);
    options->add_target_hostname(kClientTargetHostname);
    if (with_local_identities) {
      options->add_local_spiffe_id(kClientLocalSpiffeId);
      if (client_multiple_local_identities) {
        options->add_local_hostname(kClientLocalHostname);
      }
    }
  } else if (with_local_identities) {
    options->add_local_spiffe_id(kServerLocalSpiffeId);
    options->add_local_hostname(kServerLocalHostname);
  }
  return options;
}

void CheckClientStart(const Buffer& buffer, bool check_local_identity) {
  upb::Arena arena;
  s2a_proto_SessionReq* request =
      s2a_proto_SessionReq_parse(buffer.data(), buffer.size(), arena.ptr());
  ASSERT_NE(request, nullptr);
  ASSERT_TRUE(s2a_proto_SessionReq_has_client_start(request));

  s2a_proto_ClientSessionStartReq* client_start =
      s2a_proto_SessionReq_mutable_client_start(request, arena.ptr());

  // Check application protocols.
  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_proto_ClientSessionStartReq_application_protocols(
          client_start, &application_protocols_size);
  ASSERT_NE(application_protocols, nullptr);
  EXPECT_EQ(application_protocols_size, 1);
  EXPECT_TRUE(upb_strview_eql(application_protocols[0],
                              upb_strview_makez(kApplicationProtocol)));

  // Check min and max TLS versions.
  EXPECT_EQ(s2a_proto_ClientSessionStartReq_min_tls_version(client_start),
            s2a_proto_TLS1_3);
  EXPECT_EQ(s2a_proto_ClientSessionStartReq_max_tls_version(client_start),
            s2a_proto_TLS1_3);

  // Check TLS ciphersuites.
  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites =
      s2a_proto_ClientSessionStartReq_tls_ciphersuites(client_start,
                                                       &tls_ciphersuites_size);
  ASSERT_NE(tls_ciphersuites, nullptr);
  EXPECT_EQ(tls_ciphersuites_size, 3);
  EXPECT_EQ(tls_ciphersuites[0], s2a_proto_AES_128_GCM_SHA256);
  EXPECT_EQ(tls_ciphersuites[1], s2a_proto_AES_256_GCM_SHA384);
  EXPECT_EQ(tls_ciphersuites[2], s2a_proto_CHACHA20_POLY1305_SHA256);

  // Check local identity.
  const s2a_proto_Identity* local_identity =
      s2a_proto_ClientSessionStartReq_local_identity(client_start);
  if (check_local_identity) {
    ASSERT_NE(local_identity, nullptr);
    EXPECT_TRUE(s2a_proto_Identity_has_spiffe_id(local_identity));
    EXPECT_TRUE(upb_strview_eql(s2a_proto_Identity_spiffe_id(local_identity),
                                upb_strview_makez(kClientLocalSpiffeId)));
  } else {
    EXPECT_EQ(local_identity, nullptr);
  }

  // Check target identities. Note that we cannot guarantee that the order of
  // the target identities coincides with the order in which they were added to
  // the |grpc_s2a_credentials_options|.
  size_t target_identities_size;
  const s2a_proto_Identity* const* target_identities =
      s2a_proto_ClientSessionStartReq_target_identities(
          client_start, &target_identities_size);
  ASSERT_NE(target_identities, nullptr);
  for (size_t i = 0; i < target_identities_size; i++) {
    if (s2a_proto_Identity_has_spiffe_id(target_identities[i])) {
      EXPECT_TRUE(
          upb_strview_eql(s2a_proto_Identity_spiffe_id(target_identities[i]),
                          upb_strview_makez(kClientTargetSpiffeId)));
    } else if (s2a_proto_Identity_has_hostname(target_identities[i])) {
      EXPECT_TRUE(
          upb_strview_eql(s2a_proto_Identity_hostname(target_identities[i]),
                          upb_strview_makez(kClientTargetHostname)));
    } else {
      ASSERT_TRUE(0) << "Unexpected identity type.";
    }
  }

  // Check that the correct access token has been attached.
  size_t auth_mechanisms_size = 0;
  const s2a_proto_AuthenticationMechanism* const* auth_mechanisms =
      s2a_proto_SessionReq_auth_mechanisms(request, &auth_mechanisms_size);
  EXPECT_EQ(auth_mechanisms_size, 1);
  EXPECT_NE(auth_mechanisms, nullptr);
  EXPECT_TRUE(s2a_proto_AuthenticationMechanism_has_token(auth_mechanisms[0]));
  EXPECT_TRUE(upb_strview_eql(
      s2a_proto_AuthenticationMechanism_token(auth_mechanisms[0]),
      upb_strview_makez(token_manager::testing::kFakeS2AAccessToken)));
  if (check_local_identity) {
    // In this case, the user has specified a local identity for the client
    // and we check that it is the expected identity.
    const s2a_proto_Identity* auth_mechanism_identity =
        s2a_proto_AuthenticationMechanism_identity(auth_mechanisms[0]);
    if (s2a_proto_Identity_has_spiffe_id(auth_mechanism_identity)) {
      EXPECT_TRUE(
          upb_strview_eql(s2a_proto_Identity_spiffe_id(auth_mechanism_identity),
                          upb_strview_makez(kClientLocalSpiffeId)));
    } else if (s2a_proto_Identity_has_hostname(auth_mechanism_identity)) {
      EXPECT_TRUE(
          upb_strview_eql(s2a_proto_Identity_hostname(auth_mechanism_identity),
                          upb_strview_makez(kClientLocalHostname)));
    } else {
      ASSERT_TRUE(0) << "Unexpected identity type.";
    }
  } else {
    // In this case, the user did not specify any local identities for the
    // client, so no local identity should have been sent along with the token.
    EXPECT_FALSE(
        s2a_proto_AuthenticationMechanism_has_identity(auth_mechanisms[0]));
  }
}

void CheckServerStart(const Buffer& buffer, bool is_input_buffer_empty,
                      bool check_local_identities) {
  upb::Arena arena;
  s2a_proto_SessionReq* request =
      s2a_proto_SessionReq_parse(buffer.data(), buffer.size(), arena.ptr());
  ASSERT_NE(request, nullptr);
  ASSERT_TRUE(s2a_proto_SessionReq_has_server_start(request));

  s2a_proto_ServerSessionStartReq* server_start =
      s2a_proto_SessionReq_mutable_server_start(request, arena.ptr());
  ASSERT_NE(server_start, nullptr);

  // Check application protocols.
  size_t application_protocols_size;
  const upb_strview* application_protocols =
      s2a_proto_ServerSessionStartReq_application_protocols(
          server_start, &application_protocols_size);
  ASSERT_NE(application_protocols, nullptr);
  EXPECT_EQ(application_protocols_size, 1);
  EXPECT_TRUE(upb_strview_eql(application_protocols[0],
                              upb_strview_makez(kApplicationProtocol)));

  // Check min and max TLS versions.
  EXPECT_EQ(s2a_proto_ServerSessionStartReq_min_tls_version(server_start),
            s2a_proto_TLS1_3);
  EXPECT_EQ(s2a_proto_ServerSessionStartReq_max_tls_version(server_start),
            s2a_proto_TLS1_3);

  // Check TLS ciphersuites.
  size_t tls_ciphersuites_size;
  const int* tls_ciphersuites =
      s2a_proto_ServerSessionStartReq_tls_ciphersuites(server_start,
                                                       &tls_ciphersuites_size);
  ASSERT_NE(tls_ciphersuites, nullptr);
  EXPECT_EQ(tls_ciphersuites_size, 3);
  EXPECT_EQ(tls_ciphersuites[0], s2a_proto_AES_128_GCM_SHA256);
  EXPECT_EQ(tls_ciphersuites[1], s2a_proto_AES_256_GCM_SHA384);
  EXPECT_EQ(tls_ciphersuites[2], s2a_proto_CHACHA20_POLY1305_SHA256);

  // Check local identities. Note that we cannot guarantee that the order of
  // the target identities coincides with the order in which they were added to
  // the |grpc_s2a_credentials_options|.
  size_t local_identities_size;
  const s2a_proto_Identity* const* local_identities =
      s2a_proto_ServerSessionStartReq_local_identities(server_start,
                                                       &local_identities_size);
  if (check_local_identities) {
    ASSERT_NE(local_identities, nullptr);
    for (size_t i = 0; i < local_identities_size; i++) {
      if (s2a_proto_Identity_has_spiffe_id(local_identities[i])) {
        EXPECT_TRUE(
            upb_strview_eql(s2a_proto_Identity_spiffe_id(local_identities[i]),
                            upb_strview_makez(kServerLocalSpiffeId)));
      } else if (s2a_proto_Identity_has_hostname(local_identities[i])) {
        EXPECT_TRUE(
            upb_strview_eql(s2a_proto_Identity_hostname(local_identities[i]),
                            upb_strview_makez(kServerLocalHostname)));
      } else {
        ASSERT_TRUE(0) << "Unexpected identity type.";
      }
    }
  } else {
    EXPECT_EQ(local_identities_size, 0);
    EXPECT_EQ(local_identities, nullptr);
  }

  // Check the in bytes.
  if (is_input_buffer_empty) {
    EXPECT_EQ(s2a_proto_ServerSessionStartReq_in_bytes(server_start).size, 0);
  } else {
    EXPECT_TRUE(
        upb_strview_eql(s2a_proto_ServerSessionStartReq_in_bytes(server_start),
                        upb_strview_makez(kInBytes)));
  }

  // Check that the correct access token has been attached.
  size_t auth_mechanisms_size = 0;
  const s2a_proto_AuthenticationMechanism* const* auth_mechanisms =
      s2a_proto_SessionReq_auth_mechanisms(request, &auth_mechanisms_size);
  if (check_local_identities) {
    // In this case, the user has specified 2 local identities for the server
    // and we check that there is a token for each identity.
    EXPECT_EQ(auth_mechanisms_size, 2);
    EXPECT_NE(auth_mechanisms, nullptr);
    for (size_t i = 0; i < auth_mechanisms_size; i++) {
      EXPECT_TRUE(
          s2a_proto_AuthenticationMechanism_has_token(auth_mechanisms[i]));
      EXPECT_TRUE(upb_strview_eql(
          s2a_proto_AuthenticationMechanism_token(auth_mechanisms[i]),
          upb_strview_makez(token_manager::testing::kFakeS2AAccessToken)));
      const s2a_proto_Identity* auth_mechanism_identity =
          s2a_proto_AuthenticationMechanism_identity(auth_mechanisms[i]);
      if (s2a_proto_Identity_has_spiffe_id(auth_mechanism_identity)) {
        EXPECT_TRUE(upb_strview_eql(
            s2a_proto_Identity_spiffe_id(auth_mechanism_identity),
            upb_strview_makez(kServerLocalSpiffeId)));
      } else if (s2a_proto_Identity_has_hostname(auth_mechanism_identity)) {
        EXPECT_TRUE(upb_strview_eql(
            s2a_proto_Identity_hostname(auth_mechanism_identity),
            upb_strview_makez(kServerLocalHostname)));
      } else {
        ASSERT_TRUE(0) << "Unexpected identity type.";
      }
    }
  } else {
    // In this case, the user did not specify any local identities for the
    // server, so only the token for the empty identity should have been sent.
    EXPECT_EQ(auth_mechanisms_size, 1);
    EXPECT_NE(auth_mechanisms, nullptr);
    EXPECT_TRUE(
        s2a_proto_AuthenticationMechanism_has_token(auth_mechanisms[0]));
    EXPECT_TRUE(upb_strview_eql(
        s2a_proto_AuthenticationMechanism_token(auth_mechanisms[0]),
        upb_strview_makez(token_manager::testing::kFakeS2AAccessToken)));
    EXPECT_FALSE(
        s2a_proto_AuthenticationMechanism_has_identity(auth_mechanisms[0]));
  }
}

void CheckNext(const Buffer& buffer, bool expect_token,
               bool expect_local_identity) {
  upb::Arena arena;
  s2a_proto_SessionReq* request =
      s2a_proto_SessionReq_parse(buffer.data(), buffer.size(), arena.ptr());
  ASSERT_NE(request, nullptr);
  ASSERT_TRUE(s2a_proto_SessionReq_has_next(request));

  s2a_proto_SessionNextReq* next =
      s2a_proto_SessionReq_mutable_next(request, arena.ptr());
  ASSERT_NE(next, nullptr);

  // Check the in bytes.
  EXPECT_TRUE(upb_strview_eql(s2a_proto_SessionNextReq_in_bytes(next),
                              upb_strview_makez(kInBytes)));

  if (expect_token) {
    // There should be at least 1 auth mechanism attached to this message. It
    // may include a local identity if the user specified a local identity in
    // the client/server start message or if the S2A specified a local identity
    // in the response to the start message.
    size_t auth_mechanisms_size = 0;
    const s2a_proto_AuthenticationMechanism* const* auth_mechanisms =
        s2a_proto_SessionReq_auth_mechanisms(request, &auth_mechanisms_size);
    EXPECT_GE(auth_mechanisms_size, 1);
    EXPECT_NE(auth_mechanisms, nullptr);
    EXPECT_TRUE(
        s2a_proto_AuthenticationMechanism_has_token(auth_mechanisms[0]));
    EXPECT_TRUE(upb_strview_eql(
        s2a_proto_AuthenticationMechanism_token(auth_mechanisms[0]),
        upb_strview_makez(token_manager::testing::kFakeS2AAccessToken)));
    if (expect_local_identity) {
      EXPECT_TRUE(
          s2a_proto_AuthenticationMechanism_has_identity(auth_mechanisms[0]));
    }
  }
}

void CheckContext(const S2AContext& context, const std::string& description,
                  bool contains_peer_identity, bool contains_local_identity) {
  EXPECT_EQ(context.ApplicationProtocol(), kApplicationProtocol) << description;
  EXPECT_EQ(context.TlsVersion(), TlsVersion::TLS1_3) << description;
  EXPECT_EQ(context.Ciphersuite(), Ciphersuite::AES_128_GCM_SHA256)
      << description;
  EXPECT_EQ(
      context.PeerIdentity().GetIdentityType(),
      contains_peer_identity ? IdentityType::SPIFFE_ID : IdentityType::NONE)
      << description;
  EXPECT_EQ(context.PeerIdentity().GetIdentityString(),
            contains_peer_identity ? kServerLocalSpiffeId : "")
      << description;
  EXPECT_EQ(
      context.LocalIdentity().GetIdentityType(),
      contains_local_identity ? IdentityType::HOSTNAME : IdentityType::NONE)
      << description;
  EXPECT_EQ(context.LocalIdentity().GetIdentityString(),
            contains_local_identity ? kClientLocalHostname : "")
      << description;
  EXPECT_EQ(context.PeerCertFingerprint(), kPeerCertFingerprint) << description;
  EXPECT_EQ(context.LocalCertFingerprint(), kLocalCertFingerprint)
      << description;
  EXPECT_FALSE(context.IsHandshakeResumed()) << description;
}

std::unique_ptr<Buffer> CreateTestSerializedSessionResp(
    bool ok_status, bool contains_result, bool bad_state, bool bad_tls_version,
    bool bad_ciphersuite, bool contains_peer_identity,
    bool contains_local_identity, bool on_server_side,
    bool with_response_identities) {
  upb::Arena arena;
  s2a_proto_SessionResp* response = s2a_proto_SessionResp_new(arena.ptr());

  // Set the status of the |SessionResp| message.
  s2a_proto_SessionStatus* status =
      s2a_proto_SessionResp_mutable_status(response, arena.ptr());
  if (ok_status) {
    s2a_proto_SessionStatus_set_code(status, /*value=*/0);
  } else {
    s2a_proto_SessionStatus_set_code(status, /*value=*/1);
    s2a_proto_SessionStatus_set_details(
        status, upb_strview_makez(kResponseErrorMessage));
  }

  if (with_response_identities) {
    // Set the response's local identity.
    s2a_proto_Identity* response_identity =
        s2a_proto_SessionResp_mutable_local_identity(response, arena.ptr());
    if (on_server_side) {
      s2a_proto_Identity_set_spiffe_id(response_identity,
                                       upb_strview_makez(kServerLocalSpiffeId));
    } else {
      s2a_proto_Identity_set_spiffe_id(response_identity,
                                       upb_strview_makez(kClientLocalSpiffeId));
    }
  }

  // Set the out bytes of the |SessionResp| message.
  s2a_proto_SessionResp_set_out_frames(response, upb_strview_makez(kOutBytes));

  // If |contains_result| is true, populate the |SessionResult| message. The
  // in/out keys of the |SessionState| will be 32 bytes since that is the
  // expected length of a traffic secret for the AES-128-GCM-SHA256 ciphersuite.
  std::vector<char> traffic_secret(kAes128GcmTrafficSecretSize);
  if (contains_result) {
    s2a_proto_SessionResult* result =
        s2a_proto_SessionResp_mutable_result(response, arena.ptr());
    s2a_proto_SessionResult_set_application_protocol(
        result, upb_strview_makez(kApplicationProtocol));
    // If |bad_state| is false, populate the |SessionState| message.
    if (!bad_state) {
      s2a_proto_SessionState* state =
          s2a_proto_SessionResult_mutable_state(result, arena.ptr());
      s2a_proto_SessionState_set_tls_version(
          state, bad_tls_version ? static_cast<s2a_proto_TLSVersion>(3)
                                 : s2a_proto_TLS1_3);
      s2a_proto_SessionState_set_tls_ciphersuite(
          state, bad_ciphersuite ? static_cast<s2a_proto_Ciphersuite>(4)
                                 : s2a_proto_AES_128_GCM_SHA256);
      s2a_proto_SessionState_set_in_key(
          state,
          upb_strview_make(traffic_secret.data(), traffic_secret.size()));
      s2a_proto_SessionState_set_out_key(
          state,
          upb_strview_make(traffic_secret.data(), traffic_secret.size()));
      s2a_proto_SessionState_set_in_sequence(state, 0);
      s2a_proto_SessionState_set_out_sequence(state, 0);
      s2a_proto_SessionState_set_connection_id(state, kConnectionId);
      s2a_proto_SessionState_set_is_handshake_resumed(state,
                                                      kIsHandshakeResumed);
    }
    if (contains_peer_identity) {
      s2a_proto_Identity* peer_identity =
          s2a_proto_SessionResult_mutable_peer_identity(result, arena.ptr());
      s2a_proto_Identity_set_spiffe_id(peer_identity,
                                       upb_strview_makez(kServerLocalSpiffeId));
    }
    if (contains_local_identity) {
      s2a_proto_Identity* local_identity =
          s2a_proto_SessionResult_mutable_local_identity(result, arena.ptr());
      s2a_proto_Identity_set_hostname(local_identity,
                                      upb_strview_makez(kClientLocalHostname));
    }
    s2a_proto_SessionResult_set_local_cert_fingerprint(
        result, upb_strview_makez(kLocalCertFingerprint));
    s2a_proto_SessionResult_set_peer_cert_fingerprint(
        result, upb_strview_makez(kPeerCertFingerprint));
  }

  // Serialize the |SessionResp| message and return a copy that is valid outside
  // of |arena|.
  size_t buffer_len = 0;
  char* arena_buffer =
      s2a_proto_SessionResp_serialize(response, arena.ptr(), &buffer_len);
  auto buffer = absl::make_unique<Buffer>(buffer_len);
  memcpy(buffer->data(), arena_buffer, buffer_len);
  return buffer;
}

TEST(S2AProxyTest, Create) {
  const struct {
    std::string description;
    bool is_client;
    bool options_are_nullptr;
  } tests[] = {
      {"Options are nullptr.", /*is_client=*/true,
       /*options_are_nullptr=*/true},
      {"Client-side success.", /*is_client=*/true,
       /*options_are_nullptr=*/false},
      {"Server-side success.", /*is_client=*/false,
       /*options_are_nullptr=*/false},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    was_message_logged = false;
    S2AProxyOptions options = {
        FakeLogger,
        tests[i].is_client,
        kApplicationProtocol,
        kHostname,
        tests[i].options_are_nullptr
            ? nullptr
            : CreateTestOptions(tests[i].is_client,
                                /*unsupported_ciphersuite=*/false,
                                /*client_multiple_local_identities=*/false,
                                /*with_local_identities=*/true),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    if (tests[i].options_are_nullptr) {
      EXPECT_EQ(proxy, nullptr) << tests[i].description;
    } else {
      EXPECT_NE(proxy, nullptr) << tests[i].description;
    }
    EXPECT_FALSE(was_message_logged) << tests[i].description;
  }
}

TEST(S2AProxyTest, GetClientStart) {
  const struct {
    std::string description;
    bool unsupported_ciphersuite;
    bool multiple_local_identities;
    bool is_input_buffer_empty;
    Status status;
  } tests[] = {
      {"Non-empty input buffer.", /*unsupported_ciphersuite=*/false,
       /*client_multiple_local_identities=*/false,
       /*is_input_buffer_empty=*/false,
       Status(StatusCode::kFailedPrecondition,
              "Handshake has not begun, not expecting bytes.")},
      {"Unsupported ciphersuite.", /*unsupported_ciphersuite=*/true,
       /*client_multiple_local_identities=*/false,
       /*is_input_buffer_empty=*/true,
       Status(StatusCode::kFailedPrecondition, "Unsupported ciphersuite.")},
      {"Two local identities.", /*unsupported_ciphersuite=*/false,
       /*client_multiple_local_identities=*/true,
       /*is_input_buffer_empty=*/true,
       Status(StatusCode::kFailedPrecondition,
              "Client should have at most 1 local identity.")},
      {"Success.", /*unsupported_ciphersuite=*/false,
       /*client_multiple_local_identities=*/false,
       /*is_input_buffer_empty=*/true, Status()},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    was_message_logged = false;
    S2AProxyOptions options = {
        FakeLogger,
        /*is_client=*/true,
        kApplicationProtocol,
        kHostname,
        CreateTestOptions(/*is_client=*/true, tests[i].unsupported_ciphersuite,
                          tests[i].multiple_local_identities,
                          /*with_local_identities=*/true),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    ASSERT_NE(proxy, nullptr) << tests[i].description;

    // Get bytes to send to the S2A.
    auto input_buffer =
        absl::make_unique<Buffer>(tests[i].is_input_buffer_empty ? 0 : 1);
    ProxyStatus status = proxy->GetBytesForS2A(std::move(input_buffer));
    EXPECT_EQ(status.status, tests[i].status) << tests[i].description;
    if (status.status.ok()) {
      EXPECT_FALSE(was_message_logged) << tests[i].description;
      CheckClientStart(*status.buffer, /*check_local_identity=*/true);
    } else {
      EXPECT_EQ(status.buffer, nullptr) << tests[i].description;
      EXPECT_TRUE(was_message_logged) << tests[i].description;
    }
  }
}

TEST(S2AProxyTest, GetServerStart) {
  const struct {
    std::string description;
    bool unsupported_ciphersuite;
    bool is_input_buffer_empty;
    Status status;
  } tests[] = {
      {"Empty input buffer.", /*unsupported_ciphersuite=*/false,
       /*is_input_buffer_empty=*/true, Status()},
      {"Unsupported ciphersuite.", /*unsupported_ciphersuite=*/true,
       /*is_input_buffer_empty=*/false,
       Status(StatusCode::kFailedPrecondition, "Unsupported ciphersuite.")},
      {"Success.", /*unsupported_ciphersuite=*/false,
       /*is_input_buffer_empty=*/false, Status()},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    was_message_logged = false;
    S2AProxyOptions options = {
        FakeLogger,
        /*is_client=*/false,
        kApplicationProtocol,
        /*target_hostname=*/"",
        CreateTestOptions(/*is_client=*/false, tests[i].unsupported_ciphersuite,
                          /*client_multiple_local_identities=*/false,
                          /*with_local_identities=*/true),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    ASSERT_NE(proxy, nullptr) << tests[i].description;

    // Get bytes to send to the S2A.
    auto input_buffer = tests[i].is_input_buffer_empty
                            ? nullptr
                            : absl::make_unique<Buffer>(kInBytesLength);
    if (!tests[i].is_input_buffer_empty) {
      memcpy(input_buffer->data(), kInBytes, kInBytesLength);
    }
    ProxyStatus status = proxy->GetBytesForS2A(std::move(input_buffer));
    ASSERT_EQ(status.status, tests[i].status) << tests[i].description;
    if (status.status.ok()) {
      EXPECT_FALSE(was_message_logged) << tests[i].description;
      CheckServerStart(*status.buffer, tests[i].is_input_buffer_empty,
                       /*check_local_identities=*/true);
    } else {
      EXPECT_EQ(status.buffer, nullptr) << tests[i].description;
      EXPECT_TRUE(was_message_logged) << tests[i].description;
    }
  }
}

TEST(S2AProxyTest, GetNext) {
  const struct {
    std::string description;
    bool is_input_buffer_empty;
    Status status;
  } tests[] = {
      {"Input buffer is empty.", /*is_input_buffer_empty=*/true,
       Status(StatusCode::kFailedPrecondition,
              "Handshake requires bytes from peer.")},
      {"Success.", /*is_input_buffer_empty=*/false, Status()},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    was_message_logged = false;
    S2AProxyOptions options = {
        FakeLogger,
        /*is_client=*/true,
        kApplicationProtocol,
        /*target_hostname=*/"",
        CreateTestOptions(/*is_client=*/true, /*unsupported_ciphersuite=*/false,
                          /*client_multiple_local_identities=*/false,
                          /*with_local_identities=*/true),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    ASSERT_NE(proxy, nullptr) << tests[i].description;

    // Call |GetBytesForS2A| once so that all subsequent messages sent to the
    // S2A are |SessionNextReq|'s.
    ProxyStatus status = proxy->GetBytesForS2A(/*bytes_from_peer=*/nullptr);
    EXPECT_TRUE(status.status.ok());

    // Get bytes to send to the S2A.
    auto input_buffer = absl::make_unique<Buffer>(
        tests[i].is_input_buffer_empty ? 0 : kInBytesLength);
    if (!tests[i].is_input_buffer_empty) {
      memcpy(input_buffer->data(), kInBytes, kInBytesLength);
    }
    status = proxy->GetBytesForS2A(std::move(input_buffer));
    EXPECT_EQ(status.status, tests[i].status) << tests[i].description;
    if (status.status.ok()) {
      EXPECT_FALSE(was_message_logged) << tests[i].description;
      CheckNext(*status.buffer, /*expect_token=*/false,
                /*expect_local_identity=*/false);
    } else {
      EXPECT_EQ(status.buffer, nullptr) << tests[i].description;
      EXPECT_TRUE(was_message_logged) << tests[i].description;
    }
  }
}

TEST(S2AProxyTest, StartAndNext) {
  const struct {
    std::string description;
    bool is_client;
    bool with_request_identities;
    bool with_response_identities;
  } tests[] = {
      {"Client-side with request and response identities.", /*is_client=*/true,
       /*with_request_identities=*/true, /*with_response_identities=*/true},
      {"Server-side with request and response identities.", /*is_client=*/false,
       /*with_request_identities=*/true, /*with_response_identities=*/true},
      {"Client-side without request identities but with response identities.",
       /*is_client=*/true, /*with_request_identities=*/false,
       /*with_response_identities=*/true},
      {"Server-side without request identities but with response identities.",
       /*is_client=*/false, /*with_request_identities=*/false,
       /*with_response_identities=*/true},
      {"Client-side without request and response identities.",
       /*is_client=*/true, /*with_request_identities=*/false,
       /*with_response_identities=*/false},
      {"Server-side without request and response identities.",
       /*is_client=*/false, /*with_request_identities=*/false,
       /*with_response_identities=*/false},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    S2AProxyOptions options = {
        FakeLogger,
        tests[i].is_client,
        kApplicationProtocol,
        /*target_hostname=*/"",
        CreateTestOptions(tests[i].is_client,
                          /*unsupported_ciphersuite=*/false,
                          /*client_multiple_local_identities=*/false,
                          tests[i].with_request_identities),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    ASSERT_NE(proxy, nullptr) << tests[i].description;

    // Send the client/server start to S2A. The auth mechanisms in the start
    // message assert the client/server local identities iff
    // |tests[i].with_request_identities| is true; otherwise, a single auth
    // mechanism is sent that contains a token but no local identity.
    ProxyStatus status = proxy->GetBytesForS2A(/*bytes_from_peer=*/nullptr);
    EXPECT_TRUE(status.status.ok()) << tests[i].description;
    if (tests[i].is_client) {
      CheckClientStart(*status.buffer, tests[i].with_request_identities);
    } else {
      CheckServerStart(*status.buffer, /*is_input_buffer_empty=*/true,
                       tests[i].with_request_identities);
    }

    // Get the bytes for the peer from the S2A. The S2A sets a local identity in
    // the response iff |tests[i].with_response_identities| is true.
    status = proxy->GetBytesForPeer(CreateTestSerializedSessionResp(
        /*ok_status=*/true, /*contains_result=*/false,
        /*bad_state=*/false, /*bad_tls_version=*/false,
        /*bad_ciphersuite=*/false,
        /*contains_peer_identity=*/false,
        /*contains_local_identity=*/false, !tests[i].is_client,
        tests[i].with_response_identities));
    EXPECT_TRUE(status.status.ok()) << tests[i].description;

    // Send the next message to the S2A. The auth mechanisms present in this
    // message are determined as follows:
    // 1. If the S2A did not specify a local identity in the response, this
    //    message should contain the same set of auth mechanisms that were sent
    //    in the client/server start message.
    // 2. If the S2A did specify a local identity in the response, this message
    //    should contain exactly one auth mechanism and it will assert the
    //    selected local identity.
    auto buffer = absl::make_unique<Buffer>(kInBytesLength);
    memcpy(buffer->data(), kInBytes, kInBytesLength);
    status = proxy->GetBytesForS2A(std::move(buffer));
    EXPECT_TRUE(status.status.ok()) << tests[i].description;
    CheckNext(
        *status.buffer, /*expect_token=*/true,
        tests[i].with_request_identities || tests[i].with_response_identities);
  }
}

TEST(S2AProxyTest, GetBytesForPeerWithHandshakeNotFinished) {
  const struct {
    std::string description;
    bool is_input_buffer_empty;
    Status status;
  } tests[] = {
      {"Input buffer is empty.", /*is_input_buffer_empty=*/true,
       Status(StatusCode::kFailedPrecondition, "Need bytes from S2A.")},
      {"Non-ok status in response.", /*is_input_buffer_empty=*/false,
       Status(StatusCode::kInternal,
              absl::StrCat("Error from the S2A: ", kResponseErrorMessage))},
      {"Success.", /*is_input_buffer_empty=*/false, Status()},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    was_message_logged = false;
    S2AProxyOptions options = {
        FakeLogger,
        /*is_client=*/true,
        kApplicationProtocol,
        /*target_hostname=*/"",
        CreateTestOptions(/*is_client=*/true, /*unsupported_ciphersuite=*/false,
                          /*client_multiple_local_identities=*/false,
                          /*with_local_identities=*/true),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    ASSERT_NE(proxy, nullptr) << tests[i].description;

    ProxyStatus status = proxy->GetBytesForPeer(
        tests[i].is_input_buffer_empty
            ? nullptr
            : CreateTestSerializedSessionResp(
                  tests[i].status.ok(), /*contains_result=*/false,
                  /*bad_state=*/false, /*bad_tls_version=*/false,
                  /*bad_ciphersuite=*/false,
                  /*contains_peer_identity=*/false,
                  /*contains_local_identity=*/false, /*on_server_side=*/true,
                  /*with_response_identities=*/true));
    EXPECT_EQ(status.status, tests[i].status) << tests[i].description;
    if (tests[i].status.ok()) {
      std::vector<char> out_bytes(kOutBytesLength);
      memcpy(out_bytes.data(), kOutBytes, kOutBytesLength);
      EXPECT_EQ(*status.buffer, out_bytes) << tests[i].description;
    } else {
      EXPECT_EQ(status.buffer, nullptr) << tests[i].description;
      EXPECT_TRUE(was_message_logged) << tests[i].description;
    }
    EXPECT_FALSE(proxy->IsHandshakeFinished()) << tests[i].description;
  }
}

TEST(S2AProxyTest, GetBytesForPeerWithHandshakeFinished) {
  const struct {
    std::string description;
    bool bad_state;
    bool bad_tls_version;
    bool bad_ciphersuite;
    bool contains_peer_identity;
    bool contains_local_identity;
    Status status;
  } tests[] = {
      {"|SessionResult| does not have |SessionState|.", /*bad_state=*/true,
       /*bad_tls_version=*/false, /*bad_ciphersuite=*/false,
       /*contains_peer_identity=*/false, /*contains_local_identity=*/false,
       Status(StatusCode::kInvalidArgument,
              "|s2a_proto_SessionResult| is invalid.")},
      {"|SessionResult| has bad TLS version.", /*bad_state=*/false,
       /*bad_tls_version=*/true, /*bad_ciphersuite=*/false,
       /*contains_peer_identity=*/false, /*contains_local_identity=*/false,
       Status(StatusCode::kFailedPrecondition, "Unsupported TLS version.")},
      {"|SessionResult| has bad ciphersuite.", /*bad_state=*/false,
       /*bad_tls_version=*/false, /*bad_ciphersuite=*/true,
       /*contains_peer_identity=*/false, /*contains_local_identity=*/false,
       Status(StatusCode::kFailedPrecondition, "Unsupported ciphersuite.")},
      {"|SessionResult| has no peer or local identities.", /*bad_state=*/false,
       /*bad_tls_version=*/false, /*bad_ciphersuite=*/false,
       /*contains_peer_identity=*/false, /*contains_local_identity=*/false,
       Status(StatusCode::kInternal,
              "No local identity set in |s2a_proto_SessionResult|.")},
      {"Success.", /*bad_state=*/false,
       /*bad_tls_version=*/false, /*bad_ciphersuite=*/false,
       /*contains_peer_identity=*/true, /*contains_local_identity=*/true,
       Status()},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(tests); i++) {
    // Setup.
    was_message_logged = false;
    S2AProxyOptions options = {
        FakeLogger,
        /*is_client=*/true,
        kApplicationProtocol,
        /*target_hostname=*/"",
        CreateTestOptions(/*is_client=*/true, /*unsupported_ciphersuite=*/false,
                          /*client_multiple_local_identities=*/false,
                          /*with_local_identities=*/true),
        /*channel_factory=*/nullptr,
        /*channel_options=*/nullptr,
        absl::make_unique<FakeAccessTokenManager>()};
    auto proxy = S2AProxy::Create(options);
    ASSERT_NE(proxy, nullptr) << tests[i].description;

    ProxyStatus status = proxy->GetBytesForPeer(CreateTestSerializedSessionResp(
        /*ok_status=*/true, /*contains_result=*/true, tests[i].bad_state,
        tests[i].bad_tls_version, tests[i].bad_ciphersuite,
        tests[i].contains_peer_identity, tests[i].contains_local_identity,
        /*on_server_side=*/true, /*with_response_identities=*/true));
    EXPECT_EQ(status.status, tests[i].status) << tests[i].description;
    if (tests[i].status.ok()) {
      // Check the out bytes.
      std::vector<char> out_bytes(kOutBytesLength);
      memcpy(out_bytes.data(), kOutBytes, kOutBytesLength);
      EXPECT_EQ(*status.buffer, out_bytes) << tests[i].description;

      // Check that the handshake is finished.
      EXPECT_TRUE(proxy->IsHandshakeFinished()) << tests[i].description;

      // Get and check the |S2AContext|.
      absl::variant<Status, std::unique_ptr<S2AContext>> context_status =
          proxy->GetS2AContext();
      ASSERT_EQ(context_status.index(), 1) << tests[i].description;
      EXPECT_NE(absl::get<1>(context_status), nullptr) << tests[i].description;
      CheckContext(*absl::get<1>(context_status), tests[i].description,
                   tests[i].contains_peer_identity,
                   tests[i].contains_local_identity);

      // Get and check the frame protector.
      absl::StatusOr<std::unique_ptr<frame_protector::S2AFrameProtector>>
          protector = proxy->CreateFrameProtector();
      EXPECT_TRUE(protector.ok()) << tests[i].description;
      EXPECT_NE(*protector, nullptr) << tests[i].description;
    } else {
      EXPECT_EQ(status.buffer, nullptr) << tests[i].description;
      EXPECT_TRUE(was_message_logged) << tests[i].description;
    }
  }
}

TEST(S2AProxyTest, GetContextBeforeHandshakeIsFinished) {
  // Setup.
  S2AProxyOptions options = {
      FakeLogger,
      /*is_client=*/true,
      kApplicationProtocol,
      /*target_hostname=*/"",
      CreateTestOptions(/*is_client=*/true, /*unsupported_ciphersuite=*/false,
                        /*client_multiple_local_identities=*/false,
                        /*with_local_identities=*/true),
      /*channel_factory=*/nullptr,
      /*channel_options=*/nullptr,
      absl::make_unique<FakeAccessTokenManager>()};
  auto proxy = S2AProxy::Create(options);
  ASSERT_NE(proxy, nullptr);
  EXPECT_FALSE(proxy->IsHandshakeFinished());

  // Try and fail to get the |S2AContext|.
  absl::variant<Status, std::unique_ptr<S2AContext>> context_status =
      proxy->GetS2AContext();
  ASSERT_EQ(context_status.index(), 0);
  EXPECT_EQ(
      absl::get<0>(context_status),
      Status(StatusCode::kFailedPrecondition, "Handshake is not finished."));
}

TEST(S2AProxyTest, CreateFrameProtectorBeforeHandshakeIsFinished) {
  // Setup.
  S2AProxyOptions options = {
      FakeLogger,
      /*is_client=*/true,
      kApplicationProtocol,
      /*target_hostname=*/"",
      CreateTestOptions(/*is_client=*/true, /*unsupported_ciphersuite=*/false,
                        /*client_multiple_local_identities=*/false,
                        /*with_local_identities=*/true),
      /*channel_factory=*/nullptr,
      /*channel_options=*/nullptr,
      absl::make_unique<FakeAccessTokenManager>()};
  auto proxy = S2AProxy::Create(options);
  ASSERT_NE(proxy, nullptr);
  EXPECT_FALSE(proxy->IsHandshakeFinished());

  // Try and fail to create the frame protector.
  absl::StatusOr<std::unique_ptr<frame_protector::S2AFrameProtector>>
      protector_or = proxy->CreateFrameProtector();
  EXPECT_FALSE(protector_or.ok());
  EXPECT_EQ(protector_or.status(), Status(StatusCode::kFailedPrecondition,
                                          "Handshake is not finished."));
}

}  // namespace
}  // namespace s2a_proxy
}  // namespace s2a
