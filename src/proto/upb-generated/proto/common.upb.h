/* This file was generated by upbc (the upb compiler) from the input
 * file:
 *
 *     proto/common.proto
 *
 * Do not edit -- your changes will be discarded when the file is
 * regenerated. */

#ifndef SRC_PROTO_COMMON_PROTO_UPB_H_
#define SRC_PROTO_COMMON_PROTO_UPB_H_

#ifdef S2A_CORE_USE_NEW_UPB_APIS
#include "upb/msg_internal.h"
#else
#include "upb/msg.h"
#endif

#include "upb/decode.h"
#include "upb/decode_fast.h"
#include "upb/encode.h"

#include "upb/port_def.inc"

#ifdef __cplusplus
extern "C" {
#endif

struct s2a_proto_Identity;
struct s2a_proto_Identity_AttributesEntry;
typedef struct s2a_proto_Identity s2a_proto_Identity;
typedef struct s2a_proto_Identity_AttributesEntry s2a_proto_Identity_AttributesEntry;
extern const upb_msglayout s2a_proto_Identity_msginit;
extern const upb_msglayout s2a_proto_Identity_AttributesEntry_msginit;

typedef enum {
  s2a_proto_AES_128_GCM_SHA256 = 0,
  s2a_proto_AES_256_GCM_SHA384 = 1,
  s2a_proto_CHACHA20_POLY1305_SHA256 = 2
} s2a_proto_Ciphersuite;

typedef enum {
  s2a_proto_TLS1_2 = 0,
  s2a_proto_TLS1_3 = 1
} s2a_proto_TLSVersion;


/* s2a.proto.Identity */

UPB_INLINE s2a_proto_Identity *s2a_proto_Identity_new(upb_arena *arena) {
  return (s2a_proto_Identity *)_upb_msg_new(&s2a_proto_Identity_msginit, arena);
}
UPB_INLINE s2a_proto_Identity *s2a_proto_Identity_parse(const char *buf, size_t size,
                        upb_arena *arena) {
  s2a_proto_Identity *ret = s2a_proto_Identity_new(arena);
  return (ret && upb_decode(buf, size, ret, &s2a_proto_Identity_msginit, arena)) ? ret : NULL;
}
UPB_INLINE s2a_proto_Identity *s2a_proto_Identity_parse_ex(const char *buf, size_t size,
                           upb_arena *arena, int options) {
  s2a_proto_Identity *ret = s2a_proto_Identity_new(arena);
  return (ret && _upb_decode(buf, size, ret, &s2a_proto_Identity_msginit, arena, options))
      ? ret : NULL;
}
UPB_INLINE char *s2a_proto_Identity_serialize(const s2a_proto_Identity *msg, upb_arena *arena, size_t *len) {
  return upb_encode(msg, &s2a_proto_Identity_msginit, arena, len);
}

typedef enum {
  s2a_proto_Identity_identity_oneof_spiffe_id = 1,
  s2a_proto_Identity_identity_oneof_hostname = 2,
  s2a_proto_Identity_identity_oneof_uid = 4,
  s2a_proto_Identity_identity_oneof_NOT_SET = 0
} s2a_proto_Identity_identity_oneof_oneofcases;
UPB_INLINE s2a_proto_Identity_identity_oneof_oneofcases s2a_proto_Identity_identity_oneof_case(const s2a_proto_Identity* msg) { return (s2a_proto_Identity_identity_oneof_oneofcases)*UPB_PTR_AT(msg, UPB_SIZE(12, 24), int32_t); }

UPB_INLINE bool s2a_proto_Identity_has_spiffe_id(const s2a_proto_Identity *msg) { return _upb_getoneofcase(msg, UPB_SIZE(12, 24)) == 1; }
UPB_INLINE upb_strview s2a_proto_Identity_spiffe_id(const s2a_proto_Identity *msg) { return UPB_READ_ONEOF(msg, upb_strview, UPB_SIZE(4, 8), UPB_SIZE(12, 24), 1, upb_strview_make("", strlen(""))); }
UPB_INLINE bool s2a_proto_Identity_has_hostname(const s2a_proto_Identity *msg) { return _upb_getoneofcase(msg, UPB_SIZE(12, 24)) == 2; }
UPB_INLINE upb_strview s2a_proto_Identity_hostname(const s2a_proto_Identity *msg) { return UPB_READ_ONEOF(msg, upb_strview, UPB_SIZE(4, 8), UPB_SIZE(12, 24), 2, upb_strview_make("", strlen(""))); }
UPB_INLINE bool s2a_proto_Identity_has_attributes(const s2a_proto_Identity *msg) { return _upb_has_submsg_nohasbit(msg, UPB_SIZE(0, 0)); }
UPB_INLINE size_t s2a_proto_Identity_attributes_size(const s2a_proto_Identity *msg) {return _upb_msg_map_size(msg, UPB_SIZE(0, 0)); }
UPB_INLINE bool s2a_proto_Identity_attributes_get(const s2a_proto_Identity *msg, upb_strview key, upb_strview *val) { return _upb_msg_map_get(msg, UPB_SIZE(0, 0), &key, 0, val, 0); }
UPB_INLINE const s2a_proto_Identity_AttributesEntry* s2a_proto_Identity_attributes_next(const s2a_proto_Identity *msg, size_t* iter) { return (const s2a_proto_Identity_AttributesEntry*)_upb_msg_map_next(msg, UPB_SIZE(0, 0), iter); }
UPB_INLINE bool s2a_proto_Identity_has_uid(const s2a_proto_Identity *msg) { return _upb_getoneofcase(msg, UPB_SIZE(12, 24)) == 4; }
UPB_INLINE upb_strview s2a_proto_Identity_uid(const s2a_proto_Identity *msg) { return UPB_READ_ONEOF(msg, upb_strview, UPB_SIZE(4, 8), UPB_SIZE(12, 24), 4, upb_strview_make("", strlen(""))); }

UPB_INLINE void s2a_proto_Identity_set_spiffe_id(s2a_proto_Identity *msg, upb_strview value) {
  UPB_WRITE_ONEOF(msg, upb_strview, UPB_SIZE(4, 8), value, UPB_SIZE(12, 24), 1);
}
UPB_INLINE void s2a_proto_Identity_set_hostname(s2a_proto_Identity *msg, upb_strview value) {
  UPB_WRITE_ONEOF(msg, upb_strview, UPB_SIZE(4, 8), value, UPB_SIZE(12, 24), 2);
}
UPB_INLINE void s2a_proto_Identity_attributes_clear(s2a_proto_Identity *msg) { _upb_msg_map_clear(msg, UPB_SIZE(0, 0)); }
UPB_INLINE bool s2a_proto_Identity_attributes_set(s2a_proto_Identity *msg, upb_strview key, upb_strview val, upb_arena *a) { return _upb_msg_map_set(msg, UPB_SIZE(0, 0), &key, 0, &val, 0, a); }
UPB_INLINE bool s2a_proto_Identity_attributes_delete(s2a_proto_Identity *msg, upb_strview key) { return _upb_msg_map_delete(msg, UPB_SIZE(0, 0), &key, 0); }
UPB_INLINE s2a_proto_Identity_AttributesEntry* s2a_proto_Identity_attributes_nextmutable(s2a_proto_Identity *msg, size_t* iter) { return (s2a_proto_Identity_AttributesEntry*)_upb_msg_map_next(msg, UPB_SIZE(0, 0), iter); }
UPB_INLINE void s2a_proto_Identity_set_uid(s2a_proto_Identity *msg, upb_strview value) {
  UPB_WRITE_ONEOF(msg, upb_strview, UPB_SIZE(4, 8), value, UPB_SIZE(12, 24), 4);
}

/* s2a.proto.Identity.AttributesEntry */

UPB_INLINE upb_strview s2a_proto_Identity_AttributesEntry_key(const s2a_proto_Identity_AttributesEntry *msg) {
  upb_strview ret;
  _upb_msg_map_key(msg, &ret, 0);
  return ret;
}
UPB_INLINE upb_strview s2a_proto_Identity_AttributesEntry_value(const s2a_proto_Identity_AttributesEntry *msg) {
  upb_strview ret;
  _upb_msg_map_value(msg, &ret, 0);
  return ret;
}

UPB_INLINE void s2a_proto_Identity_AttributesEntry_set_value(s2a_proto_Identity_AttributesEntry *msg, upb_strview value) {
  _upb_msg_map_set_value(msg, &value, 0);
}

#ifdef __cplusplus
}  /* extern "C" */
#endif

#include "upb/port_undef.inc"

#endif  /* SRC_PROTO_COMMON_PROTO_UPB_H_ */
