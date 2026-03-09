#ifndef _HEADERS_WHITELIST_PARAMETERS_H_
#define _HEADERS_WHITELIST_PARAMETERS_H_

#include "../../core/str.h"
#include "../../core/parser/parse_param.h"

#define HWL_NAME_KEEP_REQUIRED_RFC3261 "keep_required_rfc3261"
#define HWL_NAME_KEEP_DESCRIBED_RFC3261 "keep_described_rfc3261"
#define HWL_NAME_KEEP_PATH_RFC3327 "keep_path_rfc3327"
#define HWL_NAME_KEEP_DIVERSION_RFC5806 "keep_diversion_rfc5806"
#define HWL_NAME_KEEP_RPID "keep_rpid"
#define HWL_NAME_KEEP_REFER_TO_RFC3515 "keep_refer_to_rfc3515"
#define HWL_NAME_KEEP_SIPIFMATCH_RFC3903 "keep_sipifmatch_rfc3903"
#define HWL_NAME_KEEP_SESSION_EXPIRES_RFC4028 "keep_session_expires_rfc4028"
#define HWL_NAME_KEEP_MIN_SE_RFC4028 "keep_min_se_rfc4028"
#define HWL_NAME_KEEP_ACCEPT_CONTACT_RFC3841 "keep_accept_contact_rfc3841"
#define HWL_NAME_KEEP_ALLOW_EVENTS_RFC3265 "keep_allow_events_rfc3265"
#define HWL_NAME_KEEP_REFERRED_BY_RFC3892 "keep_referred_by_rfc3892"
#define HWL_NAME_KEEP_REJECT_CONTACT_RFC3841 "keep_reject_contact_rfc3841"
#define HWL_NAME_KEEP_REQUEST_DISPOSITION_RFC3841 \
	"keep_request_disposition_rfc3841"
#define HWL_NAME_KEEP_IDENTITY_RFC4474 "keep_identity_rfc4474"
#define HWL_NAME_KEEP_IDENTITY_INFO_RFC4474 "keep_identity_info_rfc4474"
#define HWL_NAME_KEEP_PPI_RFC3325 "keep_ppi_rfc3325"
#define HWL_NAME_KEEP_PAI_RFC3325 "keep_pai_rfc3325"
#define HWL_NAME_KEEP_PRIVACY_RFC3323 "keep_privacy_rfc3323"
#define HWL_NAME_KEEP_REASON_RFC3326 "keep_reason_rfc3326"
#define HWL_NAME_KEEP_HEADER_CASE_SENSITIVE "keep_header_case_sensitive"
#define HWL_NAME_KEEP_HEADER "keep_header"
#define HWL_NAME_PARAMS_JSON_FILE "params_json_file"
#define HWL_NAME_PROFILE_NAME "profile_name"
#define HWL_NAME_PROFILE_ID "profile_id"

typedef struct hwl_mod_params {
	str profile_name;
	int required_rfc3261;
	int described_rfc3261;
	int path_rfc3327;
	int event_rfc3265;
	int diversion_rfc5806;
	int rpid;
	int refer_to_rfc3515;
	int sipifmatch_rfc3903;
	int session_expires_rfc4028;
	int min_se_rfc4028;
	int accept_contact_rfc3841;
	int allow_events_rfc3265;
	int referred_by_rfc3892;
	int reject_contact_rfc3841;
	int request_disposition_rfc3841;
	int identity_rfc4474;
	int identity_info_rfc4474;
	int ppi_rfc3325;
	int pai_rfc3325;
	int privacy_rfc3323;
	int reason_rfc3326;
	int keep_header_case_sensitive;
	str keep_header;
	param_t *keep_header_list;
} hwl_mod_params_t;

int hwl_load_params_json(str *fname, hwl_mod_params_t *default_params,
		hwl_mod_params_t **params_json_array, int *params_json_array_size,
		str *default_profile_name);
void hwl_params_json_array_free(hwl_mod_params_t **params_json_array,
		int *params_json_array_size, str *default_profile_name,
		param_t *default_keep_header_list);

#endif
