#include <stdio.h>
#include <string.h>

#include "../../core/sr_module.h"
#include "../../core/utils/srjson.h"

#include "headers_whitelist_parameters.h"

#define HWL_JSON_TYPE(_j) ((_j)->type & 0xFF)

static int hwl_add_keep_header_value(str *hdr, param_t **list)
{
	param_t *t = NULL;
	char *hname = NULL;

	if(hdr == NULL || list == NULL || hdr->s == NULL || hdr->len <= 0) {
		return -1;
	}

	t = (param_t *)pkg_malloc(sizeof(param_t));
	if(t == NULL) {
		PKG_MEM_ERROR;
		return -1;
	}
	memset(t, 0, sizeof(param_t));

	hname = (char *)pkg_malloc(hdr->len + 1);
	if(hname == NULL) {
		PKG_MEM_ERROR;
		pkg_free(t);
		return -1;
	}
	memcpy(hname, hdr->s, hdr->len);
	hname[hdr->len] = '\0';

	t->name.s = hname;
	t->name.len = hdr->len;
	t->next = *list;
	*list = t;
	return 0;
}

static void hwl_json_apply_int_opt(srjson_doc_t *jdoc, srjson_t *jitem,
		const char *key, int *dst, int profile_idx)
{
	srjson_t *jv;

	if(jdoc == NULL || jitem == NULL || key == NULL || dst == NULL) {
		return;
	}

	jv = srjson_GetObjectItem(jdoc, jitem, key);
	if(jv == NULL) {
		return;
	}

	if(HWL_JSON_TYPE(jv) == srjson_Number) {
		*dst = ((int)jv->valuedouble != 0);
		return;
	}
	if(HWL_JSON_TYPE(jv) == srjson_True) {
		*dst = 1;
		return;
	}
	if(HWL_JSON_TYPE(jv) == srjson_False) {
		*dst = 0;
		return;
	}

	LM_WARN("profile[%d] %s invalid - using default value\n", profile_idx, key);
}

static int hwl_file_read(str *fname, str *fdata)
{
	FILE *f;
	long fsize;

	fdata->s = NULL;
	fdata->len = 0;

	f = fopen(fname->s, "r");
	if(f == NULL) {
		LM_ERR("cannot open file: %.*s\n", fname->len, fname->s);
		return -1;
	}
	if(fseek(f, 0, SEEK_END) < 0) {
		LM_ERR("fseek end failed for file: %.*s\n", fname->len, fname->s);
		fclose(f);
		return -1;
	}
	fsize = ftell(f);
	if(fsize < 0) {
		LM_ERR("ftell failed for file: %.*s\n", fname->len, fname->s);
		fclose(f);
		return -1;
	}
	if(fseek(f, 0, SEEK_SET) < 0) {
		LM_ERR("fseek set failed for file: %.*s\n", fname->len, fname->s);
		fclose(f);
		return -1;
	}

	fdata->s = pkg_malloc(fsize + 1);
	if(fdata->s == NULL) {
		PKG_MEM_ERROR;
		fclose(f);
		return -1;
	}
	if(fread(fdata->s, 1, fsize, f) != (size_t)fsize) {
		LM_ERR("failed to read file: %.*s\n", fname->len, fname->s);
		pkg_free(fdata->s);
		fdata->s = NULL;
		fclose(f);
		return -1;
	}
	fclose(f);

	fdata->s[fsize] = '\0';
	fdata->len = (int)fsize;
	return 0;
}

void hwl_params_json_array_free(hwl_mod_params_t **params_json_array,
		int *params_json_array_size, str *default_profile_name,
		param_t *default_keep_header_list)
{
	int i;
	hwl_mod_params_t *arr;
	int arr_size;
	param_t *p;
	param_t *pn;

	if(params_json_array == NULL) {
		return;
	}

	arr = *params_json_array;
	arr_size = (params_json_array_size != NULL) ? *params_json_array_size : 0;

	if(arr != NULL) {
		for(i = 0; i < arr_size; i++) {
			if(arr[i].profile_name.s != NULL
					&& (default_profile_name == NULL
							|| arr[i].profile_name.s != default_profile_name->s)) {
				pkg_free(arr[i].profile_name.s);
				arr[i].profile_name.s = NULL;
				arr[i].profile_name.len = 0;
			}

			p = arr[i].keep_header_list;
			while(p != NULL && p != default_keep_header_list) {
				pn = p->next;
				if(p->name.s != NULL) {
					pkg_free(p->name.s);
					p->name.s = NULL;
					p->name.len = 0;
				}
				pkg_free(p);
				p = pn;
			}
			arr[i].keep_header_list = default_keep_header_list;
		}
		pkg_free(arr);
	}

	*params_json_array = NULL;
	if(params_json_array_size != NULL) {
		*params_json_array_size = 0;
	}
}

int hwl_load_params_json(str *fname, hwl_mod_params_t *default_params,
		hwl_mod_params_t **params_json_array, int *params_json_array_size,
		str *default_profile_name)
{
	str jdata = STR_NULL;
	srjson_doc_t jdoc;
	srjson_t *jitem;
	srjson_t *jarray;
	srjson_t *jprofile;
	srjson_t *jkeep_headers;
	srjson_t *jkeep_item;
	str keep_header_str = STR_NULL;
	char *pname;
	int i;
	int j;
	int idx;
	int obj_count = 0;
	int arr_size;
	int keep_headers_size;

	if(fname == NULL || default_params == NULL || params_json_array == NULL
			|| params_json_array_size == NULL) {
		LM_ERR("invalid parameters for json loading\n");
		return -1;
	}

	if(hwl_file_read(fname, &jdata) < 0) {
		return -1;
	}

	srjson_InitDoc(&jdoc, NULL);
	jdoc.root = srjson_Parse(&jdoc, jdata.s);
	if(jdoc.root == NULL) {
		LM_ERR("invalid json content in file: %.*s\n", fname->len, fname->s);
		pkg_free(jdata.s);
		srjson_DestroyDoc(&jdoc);
		return -1;
	}
	if(HWL_JSON_TYPE(jdoc.root) != srjson_Array) {
		LM_ERR("json root must be an array in file: %.*s\n", fname->len, fname->s);
		pkg_free(jdata.s);
		srjson_DestroyDoc(&jdoc);
		return -1;
	}

	jarray = jdoc.root;
	arr_size = srjson_GetArraySize(&jdoc, jarray);
	for(i = 0; i < arr_size; i++) {
		jitem = srjson_GetArrayItem(&jdoc, jarray, i);
		if(jitem == NULL || HWL_JSON_TYPE(jitem) != srjson_Object) {
			continue;
		}
		jprofile = srjson_GetObjectItem(&jdoc, jitem, HWL_NAME_PROFILE_NAME);
		if(jprofile == NULL || HWL_JSON_TYPE(jprofile) != srjson_String
				|| jprofile->valuestring == NULL
				|| strlen(jprofile->valuestring) == 0) {
			LM_WARN("profile[%d] without name will be skipped due to unnamed\n", i);
			continue;
		}
		obj_count++;
	}

	hwl_params_json_array_free(
			params_json_array, params_json_array_size, default_profile_name,
				default_params->keep_header_list);

	if(obj_count > 0) {
		*params_json_array = pkg_malloc(sizeof(hwl_mod_params_t) * obj_count);
		if(*params_json_array == NULL) {
			PKG_MEM_ERROR;
			pkg_free(jdata.s);
			srjson_DestroyDoc(&jdoc);
			return -1;
		}
		for(i = 0; i < obj_count; i++) {
			(*params_json_array)[i] = *default_params;
		}

		idx = 0;
		for(i = 0; i < arr_size; i++) {
			jitem = srjson_GetArrayItem(&jdoc, jarray, i);
			if(jitem == NULL || HWL_JSON_TYPE(jitem) != srjson_Object) {
				continue;
			}
			jprofile = srjson_GetObjectItem(&jdoc, jitem, HWL_NAME_PROFILE_NAME);
			if(jprofile == NULL || HWL_JSON_TYPE(jprofile) != srjson_String
					|| jprofile->valuestring == NULL
					|| strlen(jprofile->valuestring) == 0) {
				continue;
			}
			pname = pkg_malloc(strlen(jprofile->valuestring) + 1);
			if(pname == NULL) {
				PKG_MEM_ERROR;
					hwl_params_json_array_free(params_json_array, params_json_array_size,
							default_profile_name,
							default_params->keep_header_list);
					pkg_free(jdata.s);
					srjson_DestroyDoc(&jdoc);
					return -1;
				}
			strcpy(pname, jprofile->valuestring);
			(*params_json_array)[idx].profile_name.s = pname;
			(*params_json_array)[idx].profile_name.len = strlen(pname);

			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_DESCRIBED_RFC3261,
					&(*params_json_array)[idx].described_rfc3261, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_PATH_RFC3327,
					&(*params_json_array)[idx].path_rfc3327, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_DIVERSION_RFC5806,
					&(*params_json_array)[idx].diversion_rfc5806, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_RPID,
					&(*params_json_array)[idx].rpid, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_REFER_TO_RFC3515,
					&(*params_json_array)[idx].refer_to_rfc3515, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_SIPIFMATCH_RFC3903,
					&(*params_json_array)[idx].sipifmatch_rfc3903, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_SESSION_EXPIRES_RFC4028,
					&(*params_json_array)[idx].session_expires_rfc4028, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_MIN_SE_RFC4028,
					&(*params_json_array)[idx].min_se_rfc4028, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_ACCEPT_CONTACT_RFC3841,
					&(*params_json_array)[idx].accept_contact_rfc3841, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_ALLOW_EVENTS_RFC3265,
					&(*params_json_array)[idx].allow_events_rfc3265, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_REFERRED_BY_RFC3892,
					&(*params_json_array)[idx].referred_by_rfc3892, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_REJECT_CONTACT_RFC3841,
					&(*params_json_array)[idx].reject_contact_rfc3841, i);
			hwl_json_apply_int_opt(&jdoc, jitem,
					HWL_NAME_KEEP_REQUEST_DISPOSITION_RFC3841,
					&(*params_json_array)[idx].request_disposition_rfc3841, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_IDENTITY_RFC4474,
					&(*params_json_array)[idx].identity_rfc4474, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_IDENTITY_INFO_RFC4474,
					&(*params_json_array)[idx].identity_info_rfc4474, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_PPI_RFC3325,
					&(*params_json_array)[idx].ppi_rfc3325, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_PAI_RFC3325,
					&(*params_json_array)[idx].pai_rfc3325, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_PRIVACY_RFC3323,
					&(*params_json_array)[idx].privacy_rfc3323, i);
			hwl_json_apply_int_opt(&jdoc, jitem, HWL_NAME_KEEP_REASON_RFC3326,
					&(*params_json_array)[idx].reason_rfc3326, i);
			hwl_json_apply_int_opt(&jdoc, jitem,
					HWL_NAME_KEEP_HEADER_CASE_SENSITIVE,
					&(*params_json_array)[idx].keep_header_case_sensitive, i);

			jkeep_headers = srjson_GetObjectItem(&jdoc, jitem, HWL_NAME_KEEP_HEADER);
			if(jkeep_headers != NULL) {
				if(HWL_JSON_TYPE(jkeep_headers) != srjson_Array) {
					LM_WARN("profile[%d] keep_header is not an array - skipped\n",
							i);
				} else {
					keep_headers_size = srjson_GetArraySize(&jdoc, jkeep_headers);
					for(j = 0; j < keep_headers_size; j++) {
						jkeep_item = srjson_GetArrayItem(&jdoc, jkeep_headers, j);
						if(jkeep_item == NULL
								|| HWL_JSON_TYPE(jkeep_item) != srjson_String
								|| jkeep_item->valuestring == NULL
								|| strlen(jkeep_item->valuestring) == 0) {
							LM_WARN("profile[%d] keep_header[%d] invalid - skipped\n",
									i, j);
							continue;
						}
						keep_header_str.s = jkeep_item->valuestring;
						keep_header_str.len = strlen(jkeep_item->valuestring);
						if(hwl_add_keep_header_value(&keep_header_str,
									   &(*params_json_array)[idx]
												.keep_header_list)
								< 0) {
							hwl_params_json_array_free(params_json_array,
									params_json_array_size, default_profile_name,
										default_params->keep_header_list);
							pkg_free(jdata.s);
							srjson_DestroyDoc(&jdoc);
							return -1;
						}
					}
				}
			}
			idx++;
		}
	}
	*params_json_array_size = obj_count;

	LM_DBG("loaded %d objects from params json file: %.*s\n", obj_count,
			fname->len, fname->s);

	pkg_free(jdata.s);
	srjson_DestroyDoc(&jdoc);
	return 0;
}
