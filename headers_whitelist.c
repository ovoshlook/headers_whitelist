#include <string.h>

#include "../../core/data_lump.h"
#include "../../core/ut.h"

#include "headers_whitelist.h"

static int int_cmp_hwl(const void *a, const void *b)
{
	int ia = *(const int *)a;
	int ib = *(const int *)b;
	return (ia > ib) - (ia < ib);
}

int allowed_has(int v, int params_idx)
{
	hwl_mod_params_t *p;

	if(bsearch(&v, required_rfc3261,
			   required_rfc3261_size,
			   sizeof(required_rfc3261[0]), int_cmp_hwl)
			!= NULL) {
		return 1;
	}

	if(params_idx < 0 || params_idx >= hwl_params_json_array_size) {
		LM_ERR("invalid params index: %d (size=%d)\n", params_idx,
				hwl_params_json_array_size);
		return 0;
	}

	p = &hwl_params_json_array[params_idx];
	if(p->described_rfc3261
			&& bsearch(&v, described_rfc3261,
					   described_rfc3261_size,
					   sizeof(described_rfc3261[0]), int_cmp_hwl)
					   != NULL) {
		return 1;
	}
	if(p->event_rfc3265 && v == hdr_event_rfc3265) {
		return 1;
	}
	if(p->diversion_rfc5806 && v == hdr_diversion_rfc5806) {
		return 1;
	}
	if(p->rpid && v == hdr_rpid) {
		return 1;
	}
	if(p->refer_to_rfc3515 && v == hdr_refer_to_rfc3515) {
		return 1;
	}
	if(p->sipifmatch_rfc3903 && v == hdr_sipifmatch_rfc3903) {
		return 1;
	}
	if(p->session_expires_rfc4028 && v == hdr_session_expires_rfc4028) {
		return 1;
	}
	if(p->min_se_rfc4028 && v == hdr_min_se_rfc4028) {
		return 1;
	}
	if(p->accept_contact_rfc3841 && v == hdr_accept_contact_rfc3841) {
		return 1;
	}
	if(p->allow_events_rfc3265 && v == hdr_allow_events_rfc3265) {
		return 1;
	}
	if(p->referred_by_rfc3892 && v == hdr_referred_by_rfc3892) {
		return 1;
	}
	if(p->reject_contact_rfc3841 && v == hdr_reject_contact_rfc3841) {
		return 1;
	}
	if(p->request_disposition_rfc3841 && v == hdr_request_disposition_rfc3841) {
		return 1;
	}
	if(p->identity_rfc4474 && v == hdr_identity_rfc4474) {
		return 1;
	}
	if(p->identity_info_rfc4474 && v == hdr_identity_info_rfc4474) {
		return 1;
	}
	if(p->ppi_rfc3325 && v == hdr_ppi_rfc3325) {
		return 1;
	}
	if(p->pai_rfc3325 && v == hdr_pai_rfc3325) {
		return 1;
	}
	if(p->path_rfc3327 && v == hdr_path_rfc3327) {
		return 1;
	}
	if(p->privacy_rfc3323 && v == hdr_privacy_rfc3323) {
		return 1;
	}
	if(p->reason_rfc3326 && v == hdr_reason_rfc3326) {
		return 1;
	}
	return 0;
}

int is_defined(str *hdr, int params_idx)
{
	struct param *ud_hf;
	int case_sensitive;

	LM_DBG("Check if header %.*s matches user defined headers\n", hdr->len, hdr->s);
	if(params_idx < 0 || params_idx >= hwl_params_json_array_size) {
		LM_ERR("invalid params index: %d (size=%d)\n", params_idx,
				hwl_params_json_array_size);
		return 0;
	}
	case_sensitive = hwl_params_json_array[params_idx].keep_header_case_sensitive;
	for(ud_hf = hwl_params_json_array[params_idx].keep_header_list; ud_hf != NULL;
			ud_hf = ud_hf->next) {
		if((case_sensitive && str_strcmp(hdr, &ud_hf->name) == 0)
				|| (!case_sensitive && hdr->len == ud_hf->name.len
						&& strncasecmp(hdr->s, ud_hf->name.s, hdr->len) == 0)) {
			LM_DBG("Params[%d] user defined header %.*s matches %.*s\n",
					params_idx, ud_hf->name.len, ud_hf->name.s, hdr->len, hdr->s);
			return 1;
		}
	}
	return 0;
}

int hwl_whitelist_headers(sip_msg_t *msg, str *profile_name)
{
	struct hdr_field *hf;
	struct lump *l;
	int params_idx = 0;
	hwl_profile_t *p;

	if(parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse headers\n");
		return -1;
	}
	if(profile_name != NULL && profile_name->s != NULL && profile_name->len > 0) {
		for(p = hwl_profiles; p != NULL; p = p->next) {
			if(str_strcmp(&p->profile_name, profile_name) == 0) {
				params_idx = p->profile_id;
				break;
			}
		}
		if(p == NULL) {
			LM_ERR("profile not found: %.*s\n", profile_name->len, profile_name->s);
			return -1;
		}
	}
	if(params_idx < 0 || params_idx >= hwl_params_json_array_size) {
		LM_ERR("invalid params index for whitelist: %d (size=%d)\n", params_idx,
				hwl_params_json_array_size);
		return -1;
	}
	for(hf = msg->headers; hf; hf = hf->next) {
		if(allowed_has(hf->type, params_idx)) {
			continue;
		}
		if(is_defined(&hf->name, params_idx)) {
			continue;
		}

		l = del_lump(msg, hf->name.s - msg->buf, hf->len, 0);
		if(l == 0) {
			LM_ERR("failed to remove the header\n");
			return -1;
		}
	}
	LM_DBG("Whitelisted headers handled\n");
	return 1;
}
