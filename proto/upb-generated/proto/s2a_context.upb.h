/* This file was generated by upbc (the upb compiler) from the input
 * file:
 *
 *     proto/s2a_context.proto
 *
 * Do not edit -- your changes will be discarded when the file is
 * regenerated. */

#ifndef PROTO_S2A_CONTEXT_PROTO_UPB_H_
#define PROTO_S2A_CONTEXT_PROTO_UPB_H_

#include "upb/msg.h"
#include "upb/decode.h"
#include "upb/decode_fast.h"
#include "upb/encode.h"

#include "upb/port_def.inc"

#ifdef __cplusplus
extern "C" {
#endif

struct s2a_proto_S2AContext;
typedef struct s2a_proto_S2AContext s2a_proto_S2AContext;
extern const upb_msglayout s2a_proto_S2AContext_msginit;
struct s2a_proto_Identity;
extern const upb_msglayout s2a_proto_Identity_msginit;


/* s2a.proto.S2AContext */

UPB_INLINE s2a_proto_S2AContext *s2a_proto_S2AContext_new(upb_arena *arena) {
  return (s2a_proto_S2AContext *)_upb_msg_new(&s2a_proto_S2AContext_msginit, arena);
}
UPB_INLINE s2a_proto_S2AContext *s2a_proto_S2AContext_parse(const char *buf, size_t size,
                        upb_arena *arena) {
  s2a_proto_S2AContext *ret = s2a_proto_S2AContext_new(arena);
  return (ret && upb_decode(buf, size, ret, &s2a_proto_S2AContext_msginit, arena)) ? ret : NULL;
}
UPB_INLINE s2a_proto_S2AContext *s2a_proto_S2AContext_parse_ex(const char *buf, size_t size,
                           upb_arena *arena, int options) {
  s2a_proto_S2AContext *ret = s2a_proto_S2AContext_new(arena);
  return (ret && _upb_decode(buf, size, ret, &s2a_proto_S2AContext_msginit, arena, options))
      ? ret : NULL;
}
UPB_INLINE char *s2a_proto_S2AContext_serialize(const s2a_proto_S2AContext *msg, upb_arena *arena, size_t *len) {
  return upb_encode(msg, &s2a_proto_S2AContext_msginit, arena, len);
}

UPB_INLINE upb_strview s2a_proto_S2AContext_application_protocol(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(16, 16), upb_strview); }
UPB_INLINE int32_t s2a_proto_S2AContext_tls_version(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(4, 4), int32_t); }
UPB_INLINE int32_t s2a_proto_S2AContext_ciphersuite(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(8, 8), int32_t); }
UPB_INLINE bool s2a_proto_S2AContext_has_peer_identity(const s2a_proto_S2AContext *msg) { return _upb_hasbit(msg, 1); }
UPB_INLINE const struct s2a_proto_Identity* s2a_proto_S2AContext_peer_identity(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(40, 64), const struct s2a_proto_Identity*); }
UPB_INLINE bool s2a_proto_S2AContext_has_local_identity(const s2a_proto_S2AContext *msg) { return _upb_hasbit(msg, 2); }
UPB_INLINE const struct s2a_proto_Identity* s2a_proto_S2AContext_local_identity(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(44, 72), const struct s2a_proto_Identity*); }
UPB_INLINE upb_strview s2a_proto_S2AContext_peer_cert_fingerprint(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(24, 32), upb_strview); }
UPB_INLINE upb_strview s2a_proto_S2AContext_local_cert_fingerprint(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(32, 48), upb_strview); }
UPB_INLINE bool s2a_proto_S2AContext_is_handshake_resumed(const s2a_proto_S2AContext *msg) { return *UPB_PTR_AT(msg, UPB_SIZE(12, 12), bool); }

UPB_INLINE void s2a_proto_S2AContext_set_application_protocol(s2a_proto_S2AContext *msg, upb_strview value) {
  *UPB_PTR_AT(msg, UPB_SIZE(16, 16), upb_strview) = value;
}
UPB_INLINE void s2a_proto_S2AContext_set_tls_version(s2a_proto_S2AContext *msg, int32_t value) {
  *UPB_PTR_AT(msg, UPB_SIZE(4, 4), int32_t) = value;
}
UPB_INLINE void s2a_proto_S2AContext_set_ciphersuite(s2a_proto_S2AContext *msg, int32_t value) {
  *UPB_PTR_AT(msg, UPB_SIZE(8, 8), int32_t) = value;
}
UPB_INLINE void s2a_proto_S2AContext_set_peer_identity(s2a_proto_S2AContext *msg, struct s2a_proto_Identity* value) {
  _upb_sethas(msg, 1);
  *UPB_PTR_AT(msg, UPB_SIZE(40, 64), struct s2a_proto_Identity*) = value;
}
UPB_INLINE struct s2a_proto_Identity* s2a_proto_S2AContext_mutable_peer_identity(s2a_proto_S2AContext *msg, upb_arena *arena) {
  struct s2a_proto_Identity* sub = (struct s2a_proto_Identity*)s2a_proto_S2AContext_peer_identity(msg);
  if (sub == NULL) {
    sub = (struct s2a_proto_Identity*)_upb_msg_new(&s2a_proto_Identity_msginit, arena);
    if (!sub) return NULL;
    s2a_proto_S2AContext_set_peer_identity(msg, sub);
  }
  return sub;
}
UPB_INLINE void s2a_proto_S2AContext_set_local_identity(s2a_proto_S2AContext *msg, struct s2a_proto_Identity* value) {
  _upb_sethas(msg, 2);
  *UPB_PTR_AT(msg, UPB_SIZE(44, 72), struct s2a_proto_Identity*) = value;
}
UPB_INLINE struct s2a_proto_Identity* s2a_proto_S2AContext_mutable_local_identity(s2a_proto_S2AContext *msg, upb_arena *arena) {
  struct s2a_proto_Identity* sub = (struct s2a_proto_Identity*)s2a_proto_S2AContext_local_identity(msg);
  if (sub == NULL) {
    sub = (struct s2a_proto_Identity*)_upb_msg_new(&s2a_proto_Identity_msginit, arena);
    if (!sub) return NULL;
    s2a_proto_S2AContext_set_local_identity(msg, sub);
  }
  return sub;
}
UPB_INLINE void s2a_proto_S2AContext_set_peer_cert_fingerprint(s2a_proto_S2AContext *msg, upb_strview value) {
  *UPB_PTR_AT(msg, UPB_SIZE(24, 32), upb_strview) = value;
}
UPB_INLINE void s2a_proto_S2AContext_set_local_cert_fingerprint(s2a_proto_S2AContext *msg, upb_strview value) {
  *UPB_PTR_AT(msg, UPB_SIZE(32, 48), upb_strview) = value;
}
UPB_INLINE void s2a_proto_S2AContext_set_is_handshake_resumed(s2a_proto_S2AContext *msg, bool value) {
  *UPB_PTR_AT(msg, UPB_SIZE(12, 12), bool) = value;
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#include "upb/port_undef.inc"

#endif  /* PROTO_S2A_CONTEXT_PROTO_UPB_H_ */