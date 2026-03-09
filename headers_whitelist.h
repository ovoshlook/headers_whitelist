#ifndef _HEADERS_WHITELIST_H_
#define _HEADERS_WHITELIST_H_

#include "../../core/sr_module.h"
#include "../../core/parser/hf.h"

#include "headers_whitelist_parameters.h"

typedef struct hwl_profile {
	str profile_name;
	int profile_id;
	struct hwl_profile *next;
} hwl_profile_t;

extern hwl_mod_params_t *hwl_params_json_array;
extern int hwl_params_json_array_size;
extern hwl_profile_t *hwl_profiles;

extern hdr_types_t required_rfc3261[];
extern hdr_types_t described_rfc3261[];
extern int required_rfc3261_size;
extern int described_rfc3261_size;
extern hdr_types_t hdr_event_rfc3265;
extern hdr_types_t hdr_diversion_rfc5806;
extern hdr_types_t hdr_rpid;
extern hdr_types_t hdr_refer_to_rfc3515;
extern hdr_types_t hdr_sipifmatch_rfc3903;
extern hdr_types_t hdr_session_expires_rfc4028;
extern hdr_types_t hdr_min_se_rfc4028;
extern hdr_types_t hdr_accept_contact_rfc3841;
extern hdr_types_t hdr_allow_events_rfc3265;
extern hdr_types_t hdr_referred_by_rfc3892;
extern hdr_types_t hdr_reject_contact_rfc3841;
extern hdr_types_t hdr_request_disposition_rfc3841;
extern hdr_types_t hdr_identity_rfc4474;
extern hdr_types_t hdr_identity_info_rfc4474;
extern hdr_types_t hdr_ppi_rfc3325;
extern hdr_types_t hdr_pai_rfc3325;
extern hdr_types_t hdr_path_rfc3327;
extern hdr_types_t hdr_privacy_rfc3323;
extern hdr_types_t hdr_reason_rfc3326;

int allowed_has(int v, int params_idx);
int is_defined(str *hdr, int params_idx);
int hwl_whitelist_headers(sip_msg_t *msg, str *profile_name);

#endif
