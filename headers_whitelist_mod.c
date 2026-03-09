/**
 * Copyright (C) 2026 Iurii Gorlichenko (uricomms)
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*!
 * \file
 * \brief Kamailio headers_whitelist :: Module interface
 * \ingroup headers_whitelist
 * Module: \ref headers_whitelist
 */

/*! \defgroup headers_whitelist Kamailio :: Headers whitelisting
 *
 * This module removes the SIP headers aside whitelisted headers.
 * The script interpreter gets the SIP messages with full content, so all
 * existing functionality is preserved.
 * @{
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../core/sr_module.h"
#include "../../core/mod_fix.h"
#include "../../core/kemi.h"
#include "../../core/rpc.h"
#include "../../core/ut.h"

#include "../../core/cfg/cfg.h"
#include "../../core/parser/parse_param.h"
#include "../../core/parser/hf.h"

#include "headers_whitelist.h"
#include "headers_whitelist_parameters.h"


MODULE_VERSION

static hwl_mod_params_t hwl_params = {
	.profile_name = STR_NULL,
	.required_rfc3261 = 1,
	.described_rfc3261 = 1,
	.path_rfc3327 = 1,
	.event_rfc3265 = 1,
	.diversion_rfc5806 = 1,
	.rpid = 1,
	.refer_to_rfc3515 = 1,
	.sipifmatch_rfc3903 = 1,
	.session_expires_rfc4028 = 1,
	.min_se_rfc4028 = 1,
	.accept_contact_rfc3841 = 1,
	.allow_events_rfc3265 = 1,
	.referred_by_rfc3892 = 1,
	.reject_contact_rfc3841 = 1,
	.request_disposition_rfc3841 = 1,
	.identity_rfc4474 = 1,
	.identity_info_rfc4474 = 1,
	.ppi_rfc3325 = 1,
	.pai_rfc3325 = 1,
	.privacy_rfc3323 = 1,
	.reason_rfc3326 = 1,
	.keep_header_case_sensitive = 1,
	.keep_header = STR_NULL,
	.keep_header_list = NULL
};
static str hwl_params_json_file = STR_NULL;
hwl_mod_params_t *hwl_params_json_array = NULL;
int hwl_params_json_array_size = 0;
hwl_profile_t *hwl_profiles = NULL;
static str hwl_default_profile_name = str_init("default");

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);
static int hwl_reload_config(void);

static int whitelist_headers_f(sip_msg_t *msg);
static int whitelist_headers_with_profile_f(sip_msg_t *msg, char *p1, char *p2);
static int ki_whitelist_headers(sip_msg_t *msg);
static int ki_whitelist_headers_with_profile(sip_msg_t *msg, str *profile_name);
int whl_param(modparam_t type, void *val);
static int hwl_profile_name_fillup(hwl_mod_params_t *profile, int profile_idx);
static void hwl_profiles_free(void);
static void hwl_rpc_reload(rpc_t *rpc, void *ctx);
static void hwl_rpc_profiles(rpc_t *rpc, void *ctx);

static const char *hwl_rpc_reload_doc[] = {
	"Reload headers_whitelist profiles and parameters",
	0
};

static const char *hwl_rpc_profiles_doc[] = {
	"List loaded headers_whitelist profiles",
	0
};

static rpc_export_t hwl_rpc_methods[] = {
	{"hwl.reload", hwl_rpc_reload, hwl_rpc_reload_doc, 0},
	{"hwl.profiles_list", hwl_rpc_profiles, hwl_rpc_profiles_doc,
			RPC_RET_ARRAY},
	{0, 0, 0, 0}
};

static cmd_export_t cmds[] = {
	{"whitelist_headers", (cmd_function)whitelist_headers_f, 0, 0, 0, REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"whitelist_headers_with_profile", (cmd_function)whitelist_headers_with_profile_f,
			1, fixup_spve_null, 0,
			REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{0, 0, 0, 0, 0, 0}
};
static param_export_t params[]  = {
    {HWL_NAME_KEEP_DESCRIBED_RFC3261,PARAM_INT, &hwl_params.described_rfc3261},
    {HWL_NAME_KEEP_PATH_RFC3327,PARAM_INT, &hwl_params.path_rfc3327},
    {HWL_NAME_KEEP_DIVERSION_RFC5806,PARAM_INT, &hwl_params.diversion_rfc5806},
    {HWL_NAME_KEEP_RPID,PARAM_INT, &hwl_params.rpid},
    {HWL_NAME_KEEP_REFER_TO_RFC3515,PARAM_INT, &hwl_params.refer_to_rfc3515},
    {HWL_NAME_KEEP_SIPIFMATCH_RFC3903,PARAM_INT, &hwl_params.sipifmatch_rfc3903},
    {HWL_NAME_KEEP_SESSION_EXPIRES_RFC4028,PARAM_INT, &hwl_params.session_expires_rfc4028},
    {HWL_NAME_KEEP_MIN_SE_RFC4028,PARAM_INT, &hwl_params.min_se_rfc4028},
    {HWL_NAME_KEEP_ACCEPT_CONTACT_RFC3841,PARAM_INT, &hwl_params.accept_contact_rfc3841},
    {HWL_NAME_KEEP_ALLOW_EVENTS_RFC3265,PARAM_INT, &hwl_params.allow_events_rfc3265},
    {HWL_NAME_KEEP_REFERRED_BY_RFC3892,PARAM_INT, &hwl_params.referred_by_rfc3892},
    {HWL_NAME_KEEP_REJECT_CONTACT_RFC3841,PARAM_INT, &hwl_params.reject_contact_rfc3841},
    {HWL_NAME_KEEP_REQUEST_DISPOSITION_RFC3841,PARAM_INT, &hwl_params.request_disposition_rfc3841},
    {HWL_NAME_KEEP_IDENTITY_RFC4474,PARAM_INT, &hwl_params.identity_rfc4474},
    {HWL_NAME_KEEP_IDENTITY_INFO_RFC4474,PARAM_INT, &hwl_params.identity_info_rfc4474},
    {HWL_NAME_KEEP_PPI_RFC3325,PARAM_INT, &hwl_params.ppi_rfc3325},
    {HWL_NAME_KEEP_PAI_RFC3325,PARAM_INT, &hwl_params.pai_rfc3325},
    {HWL_NAME_KEEP_PRIVACY_RFC3323,PARAM_INT, &hwl_params.privacy_rfc3323},
    {HWL_NAME_KEEP_REASON_RFC3326,PARAM_INT, &hwl_params.reason_rfc3326},
	{HWL_NAME_KEEP_HEADER_CASE_SENSITIVE,PARAM_INT, &hwl_params.keep_header_case_sensitive},
	{HWL_NAME_KEEP_HEADER,PARAM_STRING | PARAM_USE_FUNC, (void *)whl_param},
	{HWL_NAME_PARAMS_JSON_FILE, PARAM_STR, &hwl_params_json_file},
	{0, 0, 0}
};

/** module exports */
struct module_exports exports = {
	"headers_whitelist",		 /* module name */
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,			 /* exported  functions */
	params,			 /* exported parameters */
	hwl_rpc_methods, /* exported rpc functions */
	0,				 /* exported pseudo-variables */
	0,				 /* response handling function */
	mod_init,		 /* module initialization function */
	child_init,		 /* child initialization function */
	destroy			 /* destroy function */
};

hdr_types_t allowed_predefined_headers[55] = {};
hdr_types_t required_rfc3261[] = {
	HDR_VIA_T /*!< Via header field */,
	HDR_TO_T /*!< To header field */,
	HDR_FROM_T /*!< From header field */,
	HDR_CSEQ_T /*!< CSeq header field */,
	HDR_CALLID_T /*!< Call-Id header field */,
};
int required_rfc3261_size = sizeof(required_rfc3261) / sizeof(required_rfc3261[0]);

hdr_types_t described_rfc3261[] = {
	HDR_CONTACT_T/*!< Contact header field */,
	HDR_MAXFORWARDS_T /*!< MaxForwards header field */,
	HDR_ROUTE_T /*!< Route header field */,
	HDR_RECORDROUTE_T /*!< Record-Route header field */,
	HDR_CONTENTTYPE_T /*!< Content-Type header field */,
	HDR_CONTENTLENGTH_T /*!< Content-Length header field */,
	HDR_AUTHORIZATION_T /*!< Authorization header field */,
	HDR_EXPIRES_T /*!< Expires header field */,
	HDR_MIN_EXPIRES_T  /*!< Min-Expires header */,
	HDR_PROXYAUTH_T /*!< Proxy-Authorization hdr field */,
	HDR_SUPPORTED_T /*!< Supported  header field */,
	HDR_REQUIRE_T /*!< Require header */,
	HDR_PROXYREQUIRE_T /*!< Proxy-Require header field */,
	HDR_UNSUPPORTED_T /*!< Unsupported header field */,
	HDR_ALLOW_T /*!< Allow header field */,
	HDR_ACCEPT_T /*!< Accept header field */,
	HDR_ACCEPTLANGUAGE_T /*!< Accept-Language header field */,
	HDR_ORGANIZATION_T /*!< Organization header field */,
	HDR_PRIORITY_T /*!< Priority header field */,
	HDR_SUBJECT_T /*!< Subject header field */,
	HDR_USERAGENT_T /*!< User-Agent header field */,
	HDR_SERVER_T /*!< Server header field */,
	HDR_CONTENTDISPOSITION_T /*!< Content-Disposition hdr field */,
	HDR_CONTENTENCODING_T /*!< Content-Encoding header */,
	HDR_WWW_AUTHENTICATE_T /*!< WWW-Authenticate header field */,
	HDR_PROXY_AUTHENTICATE_T /*!< Proxy-Authenticate header field */,
	HDR_DATE_T /*!< Date header field */,
	HDR_RETRY_AFTER_T /*!< Retry-After header field */,
	HDR_CALLINFO_T /*!< Call-Info header field*/,
};
int described_rfc3261_size =
		sizeof(described_rfc3261) / sizeof(described_rfc3261[0]);

hdr_types_t hdr_event_rfc3265 = HDR_EVENT_T;
hdr_types_t hdr_diversion_rfc5806 = HDR_DIVERSION_T;
hdr_types_t hdr_rpid = HDR_RPID_T;
hdr_types_t hdr_refer_to_rfc3515 = HDR_REFER_TO_T;
hdr_types_t hdr_sipifmatch_rfc3903 = HDR_SIPIFMATCH_T;
hdr_types_t hdr_session_expires_rfc4028 = HDR_SESSIONEXPIRES_T;
hdr_types_t hdr_min_se_rfc4028 = HDR_MIN_SE_T;
hdr_types_t hdr_accept_contact_rfc3841 = HDR_ACCEPTCONTACT_T;
hdr_types_t hdr_allow_events_rfc3265 = HDR_ALLOWEVENTS_T;
hdr_types_t hdr_referred_by_rfc3892 = HDR_REFERREDBY_T;
hdr_types_t hdr_reject_contact_rfc3841 = HDR_REJECTCONTACT_T;
hdr_types_t hdr_request_disposition_rfc3841 = HDR_REQUESTDISPOSITION_T;
hdr_types_t hdr_identity_rfc4474 = HDR_IDENTITY_T;
hdr_types_t hdr_identity_info_rfc4474 = HDR_IDENTITY_INFO_T;
hdr_types_t hdr_ppi_rfc3325 = HDR_PPI_T;
hdr_types_t hdr_pai_rfc3325 = HDR_PAI_T;
hdr_types_t hdr_path_rfc3327 = HDR_PATH_T;
hdr_types_t hdr_privacy_rfc3323 = HDR_PRIVACY_T;
hdr_types_t hdr_reason_rfc3326 = HDR_REASON_T;

static int parse_keep_headers(hwl_mod_params_t *profile, int profile_idx)
{
	str profile_name = STR_NULL;
	struct param *ud_hf;

	if(profile == NULL) {
		LM_ERR("invalid profile pointer while parsing keep headers\n");
		return -1;
	}
	profile_name = profile->profile_name;
	for(ud_hf = profile->keep_header_list; ud_hf != NULL; ud_hf = ud_hf->next) {
		if(ud_hf->name.s == NULL || ud_hf->name.len <= 0) {
			LM_ERR("empty user defined header in profile idx: %d\n",
					profile_idx);
			return -1;
		}
		LM_INFO("profile[%d][%.*s] has user defined header to keep: %.*s\n",
				profile_idx, profile_name.len, profile_name.s, ud_hf->name.len,
				ud_hf->name.s);
	}
	return 0;
}

static int add_headers_to_list(str *ud_hdr) {
	param_t *t;
	while(1) {
		t = (param_t *)pkg_malloc(sizeof(param_t));
		if(t == 0) {
			PKG_MEM_ERROR;
			LM_ERR("unable to allocate memory to parse value of the parameter %.*s\n", ud_hdr->len,ud_hdr->s);
			return -1;
		}
		switch(parse_param(ud_hdr, CLASS_ANY, 0, t)) {
			case 0:
				break;
			case 1:
				goto ok;
			default:
				LM_ERR("unable to parse user defined headers %.*s\n", ud_hdr->len,ud_hdr->s);
				goto error;
		}

		t->next = hwl_params.keep_header_list;
		hwl_params.keep_header_list = t;

	}

error:
	if(t) {
		pkg_free(t);
	}
	return -2;
ok:
	t->next = hwl_params.keep_header_list;
	hwl_params.keep_header_list = t;
	return 0;
}

int whl_param(modparam_t type, void *val) {

	str ud_hdr;
	if(val == NULL)
		return -1;

	ud_hdr.s = (char *)val;
	ud_hdr.len = strlen(ud_hdr.s);
	LM_DBG("User defined headers: %.*s\n",ud_hdr.len,ud_hdr.s);
	// append to existing list
	if (hwl_params.keep_header_list != NULL) {
		if (add_headers_to_list(&ud_hdr) < 0) {
			LM_ERR("unable to parse user defined headers\n");
			return -1;
		};
	} 
	// init hwl_keep_header_list
	else {
		if(parse_params(&ud_hdr, CLASS_ANY, 0, &hwl_params.keep_header_list) < 0) {
			LM_ERR("unable to parse user defined headers\n");
			return -1;
		}
	}
	return 0;
}

static int int_cmp(const void *a, const void *b) {
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return (ia > ib) - (ia < ib);
}

static int mod_init(void) {
	qsort(allowed_predefined_headers,
			sizeof(allowed_predefined_headers)
					/ sizeof(allowed_predefined_headers[0]),
			sizeof(allowed_predefined_headers[0]), int_cmp);

	if(hwl_reload_config() < 0) {
		return -1;
	}

	return 0;
}

static int hwl_reload_config(void)
{

	hwl_params_json_array_free(&hwl_params_json_array,
			&hwl_params_json_array_size, &hwl_default_profile_name,
			hwl_params.keep_header_list);

	if(hwl_params_json_file.s != NULL && hwl_params_json_file.len > 0) {
		if (hwl_params.keep_header_case_sensitive == 0 ) {
			LM_WARN("[keep_header_case_sensitive] will be ignored and rewritten by profile defined parameter\n");
		}
		
		if(hwl_load_params_json(&hwl_params_json_file, &hwl_params,
				   &hwl_params_json_array, &hwl_params_json_array_size,
				   &hwl_default_profile_name)
				< 0) {
			LM_ERR("failed to load params from json file: %.*s\n",
					hwl_params_json_file.len, hwl_params_json_file.s);
			return -1;
		}

	} else {
		hwl_params_json_array = pkg_malloc(sizeof(hwl_mod_params_t));
		if(hwl_params_json_array == NULL) {
			PKG_MEM_ERROR;
			return -1;
		}
		hwl_params_json_array[0] = hwl_params;
		hwl_params_json_array[0].profile_name = hwl_default_profile_name;
		hwl_params_json_array_size = 1;
		LM_INFO("no profiles file found. using module parameters defined setup as profile [%*.s]\n",
			hwl_default_profile_name.len,
			hwl_default_profile_name.s);
	}
	
	{
		int i;
		for(i = 0; i < hwl_params_json_array_size; i++) {
			if(parse_keep_headers(&hwl_params_json_array[i], i) < 0) {
				LM_ERR("invalid user defined headers in params array\n");
				return -1;
			}
		}
	}
	hwl_profiles_free();
	{
		int i;
		for(i = 0; i < hwl_params_json_array_size; i++) {
			if(hwl_profile_name_fillup(&hwl_params_json_array[i], i) < 0) {
				LM_ERR("failed to create profiles list\n");
				return -1;
			}
		}
	}
    
	return 0;
}

static int child_init(int rank) {
    return 0;
}

static void hwl_rpc_reload(rpc_t *rpc, void *ctx)
{
	if(hwl_reload_config() < 0) {
		rpc->fault(ctx, 500, "failed to reload headers_whitelist configuration");
		return;
	}

	rpc->add(ctx, "s", "ok");
}

static void hwl_rpc_profiles(rpc_t *rpc, void *ctx)
{
	void *ah;
	void *ih;
	void *kh;
	hwl_profile_t *p;
	hwl_mod_params_t *pp;
	param_t *it;

	if(rpc->add(ctx, "[", &ah) < 0) {
		rpc->fault(ctx, 500, "failed to create rpc array");
		return;
	}

	for(p = hwl_profiles; p != NULL; p = p->next) {
		if(p->profile_id < 0 || p->profile_id >= hwl_params_json_array_size) {
			rpc->fault(ctx, 500, "invalid profile id: %d", p->profile_id);
			return;
		}
		pp = &hwl_params_json_array[p->profile_id];

		if(rpc->array_add(ah, "{", &ih) < 0) {
			rpc->fault(ctx, 500, "failed to create rpc profile struct");
			return;
		}
		if(rpc->struct_add(ih, "Sd", HWL_NAME_PROFILE_NAME, &p->profile_name,
				   HWL_NAME_PROFILE_ID, p->profile_id)
				< 0) {
			rpc->fault(ctx, 500, "failed to add rpc profile data");
			return;
		}
		if(rpc->struct_add(ih, "dddddddddddddddddddd",
				   HWL_NAME_KEEP_DESCRIBED_RFC3261, pp->described_rfc3261,
				   HWL_NAME_KEEP_PATH_RFC3327, pp->path_rfc3327,
				   HWL_NAME_KEEP_DIVERSION_RFC5806, pp->diversion_rfc5806,
				   HWL_NAME_KEEP_RPID, pp->rpid, HWL_NAME_KEEP_REFER_TO_RFC3515,
				   pp->refer_to_rfc3515, HWL_NAME_KEEP_SIPIFMATCH_RFC3903,
				   pp->sipifmatch_rfc3903,
				   HWL_NAME_KEEP_SESSION_EXPIRES_RFC4028,
				   pp->session_expires_rfc4028, HWL_NAME_KEEP_MIN_SE_RFC4028,
				   pp->min_se_rfc4028, HWL_NAME_KEEP_ACCEPT_CONTACT_RFC3841,
				   pp->accept_contact_rfc3841, HWL_NAME_KEEP_ALLOW_EVENTS_RFC3265,
				   pp->allow_events_rfc3265, HWL_NAME_KEEP_REFERRED_BY_RFC3892,
				   pp->referred_by_rfc3892, HWL_NAME_KEEP_REJECT_CONTACT_RFC3841,
				   pp->reject_contact_rfc3841,
				   HWL_NAME_KEEP_REQUEST_DISPOSITION_RFC3841,
				   pp->request_disposition_rfc3841, HWL_NAME_KEEP_IDENTITY_RFC4474,
				   pp->identity_rfc4474, HWL_NAME_KEEP_IDENTITY_INFO_RFC4474,
				   pp->identity_info_rfc4474, HWL_NAME_KEEP_PPI_RFC3325,
				   pp->ppi_rfc3325, HWL_NAME_KEEP_PAI_RFC3325, pp->pai_rfc3325,
				   HWL_NAME_KEEP_PRIVACY_RFC3323, pp->privacy_rfc3323,
				   HWL_NAME_KEEP_REASON_RFC3326, pp->reason_rfc3326,
				   HWL_NAME_KEEP_HEADER_CASE_SENSITIVE,
				   pp->keep_header_case_sensitive)
				< 0) {
			rpc->fault(ctx, 500, "failed to add rpc profile flags");
			return;
		}
		if(rpc->struct_add(ih, "[", HWL_NAME_KEEP_HEADER, &kh) < 0) {
			rpc->fault(ctx, 500, "failed to add keep_header array");
			return;
		}
		for(it = pp->keep_header_list; it != NULL; it = it->next) {
			if(rpc->array_add(kh, "S", &it->name) < 0) {
				rpc->fault(ctx, 500, "failed to add keep_header item");
				return;
			}
		}
	}
}

static void hwl_profiles_free(void)
{
	hwl_profile_t *p;
	hwl_profile_t *pn;

	p = hwl_profiles;
	while(p != NULL) {
		pn = p->next;
		if(p->profile_name.s != NULL) {
			pkg_free(p->profile_name.s);
			p->profile_name.s = NULL;
			p->profile_name.len = 0;
		}
		pkg_free(p);
		p = pn;
	}
	hwl_profiles = NULL;
}

static int hwl_profile_name_fillup(hwl_mod_params_t *profile, int profile_idx)
{
	hwl_profile_t *p;
	hwl_profile_t *n;
	hwl_profile_t *tail;
	char *cname;

	if(profile == NULL) {
		LM_ERR("invalid profile pointer for profiles fillup\n");
		return -1;
	}
	if(profile->profile_name.s == NULL || profile->profile_name.len <= 0) {
		return 0;
	}

	for(p = hwl_profiles; p != NULL; p = p->next) {
		if(str_strcmp(&profile->profile_name, &p->profile_name) == 0) {
			return 0;
		}
	}

	n = (hwl_profile_t *)pkg_malloc(sizeof(hwl_profile_t));
	if(n == NULL) {
		PKG_MEM_ERROR;
		return -1;
	}
	memset(n, 0, sizeof(hwl_profile_t));

	cname = pkg_malloc(profile->profile_name.len + 1);
	if(cname == NULL) {
		PKG_MEM_ERROR;
		pkg_free(n);
		return -1;
	}
	memcpy(cname, profile->profile_name.s, profile->profile_name.len);
	cname[profile->profile_name.len] = '\0';

	n->profile_name.s = cname;
	n->profile_name.len = profile->profile_name.len;
	n->profile_id = profile_idx;
	n->next = NULL;

	if(hwl_profiles == NULL) {
		hwl_profiles = n;
	} else {
		tail = hwl_profiles;
		while(tail->next != NULL) {
			tail = tail->next;
		}
		tail->next = n;
	}

	LM_DBG("profile added: idx=%d name=%.*s\n", profile_idx, n->profile_name.len,
			n->profile_name.s);
	return 0;
}

static int whitelist_headers_f(sip_msg_t *msg)
{
	if(hwl_params_json_file.s != NULL && hwl_params_json_file.len > 0
			&& hwl_params_json_array != NULL && hwl_params_json_array_size > 0) {
				LM_WARN("whitelist_headers() called without profile while json "
						"configuration is enabled; first profile will be used: "
						"id=0 name=%.*s\n",
						hwl_params_json_array[0].profile_name.len,
						hwl_params_json_array[0].profile_name.s);
		}
	
	return hwl_whitelist_headers(msg, &hwl_params_json_array[0].profile_name);
}

static int whitelist_headers_with_profile_f(
		sip_msg_t *msg, char *p1, char *p2)
{
	str profile_name = STR_NULL;

	if(fixup_get_svalue(msg, (gparam_p)p1, &profile_name) != 0
			|| profile_name.s == NULL || profile_name.len <= 0) {
		LM_ERR("cannot get profile name parameter\n");
		return -1;
	}

	return hwl_whitelist_headers(msg, &profile_name);
}

static int ki_whitelist_headers(sip_msg_t *msg)
{
	return hwl_whitelist_headers(msg, &hwl_default_profile_name);
}

static int ki_whitelist_headers_with_profile(sip_msg_t *msg, str *profile_name)
{
	return hwl_whitelist_headers(msg, profile_name);
}

/* clang-format off */
static sr_kemi_t sr_kemi_headers_whitelist_exports[] = {
	{ str_init("headers_whitelist"), str_init("whitelist_headers"),
		SR_KEMIP_INT, ki_whitelist_headers,
		{ SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},
	{ str_init("headers_whitelist"), str_init("whitelist_headers_with_profile"),
		SR_KEMIP_INT, ki_whitelist_headers_with_profile,
		{ SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},
	{ {0, 0}, {0, 0}, 0, NULL, { 0, 0, 0, 0, 0, 0 } }
};
/* clang-format on */

int mod_register(char *path, int *dlflags, void *p1, void *p2)
{
	sr_kemi_modules_add(sr_kemi_headers_whitelist_exports);
	return 0;
}

static void destroy(void)
{
	hwl_profiles_free();

	hwl_params_json_array_free(&hwl_params_json_array,
			&hwl_params_json_array_size, &hwl_default_profile_name,
			hwl_params.keep_header_list);
}
