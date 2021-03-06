/* This file was generated by upbc (the upb compiler) from the input
 * file:
 *
 *     proto/s2a_context.proto
 *
 * Do not edit -- your changes will be discarded when the file is
 * regenerated. */

#include <stddef.h>

#ifdef S2A_CORE_USE_NEW_UPB_APIS
#include "upb/msg_internal.h"
#else
#include "upb/msg.h"
#endif

#include "src/proto/upb-generated/proto/s2a_context.upb.h"
#include "src/proto/upb-generated/proto/common.upb.h"

#include "upb/port_def.inc"

static const upb_msglayout *const s2a_proto_S2AContext_submsgs[1] = {
  &s2a_proto_Identity_msginit,
};

static const upb_msglayout_field s2a_proto_S2AContext__fields[8] = {
  {1, UPB_SIZE(16, 16), 0, 0, 9, 1},
  {2, UPB_SIZE(4, 4), 0, 0, 14, 1},
  {3, UPB_SIZE(8, 8), 0, 0, 14, 1},
  {4, UPB_SIZE(40, 64), 1, 0, 11, 1},
  {5, UPB_SIZE(44, 72), 2, 0, 11, 1},
  {6, UPB_SIZE(24, 32), 0, 0, 12, 1},
  {7, UPB_SIZE(32, 48), 0, 0, 12, 1},
  {8, UPB_SIZE(12, 12), 0, 0, 8, 1},
};

const upb_msglayout s2a_proto_S2AContext_msginit = {
  &s2a_proto_S2AContext_submsgs[0],
  &s2a_proto_S2AContext__fields[0],
  UPB_SIZE(48, 80), 8, false, 255,
};

#include "upb/port_undef.inc"

