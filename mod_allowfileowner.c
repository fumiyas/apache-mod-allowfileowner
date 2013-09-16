/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Apache HTTPD: mod_allowfileowner - Restrict owner of static content files
 * Copyright (c) 2013 SATOH Fumiyasu @ OSS Technology Corp., Japan
 *
 * Development home: <https://github.com/fumiyas/apache-mod-allowfileowner>
 * Author's home: <http://fumiyas.github.io/>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "mpm_common.h"
#include "util_filter.h"

static const char filter_name[] = "ALLOWFILEOWNER";

module AP_MODULE_DECLARE_DATA allowfileowner_module;

typedef struct {
    apr_array_header_t *owner_uids;
} allowfileowner_dir_config;

static void *create_dir_config(apr_pool_t *p, char *d)
{
    allowfileowner_dir_config *conf = apr_pcalloc(p, sizeof(*conf));

    conf->owner_uids = apr_array_make(p, 1, sizeof(apr_uid_t));

    return conf;
}

static const char *allowfileowner_cmd(cmd_parms *cmd, void *in_conf,
                                      const char *args)
{
    allowfileowner_dir_config *conf = in_conf;
    const char *username;
    apr_uid_t *uidp;

    while (*args) {
        username = ap_getword_conf(cmd->pool, &args);
	uidp = (apr_uid_t *) apr_array_push(conf->owner_uids);
	*uidp = (apr_uid_t) ap_uname2id(username);
    }

    return NULL;
}

static int allowfileowner_check(request_rec *r, apr_file_t *fd)
{
    allowfileowner_dir_config *d;
    const char *userdir_user;
    apr_finfo_t finfo;
    apr_status_t status;
    int i;

    d = (allowfileowner_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &allowfileowner_module);

    userdir_user = apr_table_get(r->notes, "mod_userdir_user");

    if (!d->owner_uids->nelts && !userdir_user) {
	return HTTP_OK;
    }

    status = apr_file_info_get(&finfo, APR_FINFO_OWNER, fd);
    if (status != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
		      "allowfileowner_filter: "
		      "apr_file_info_get() failed: %s",
		      r->filename);
	return HTTP_FORBIDDEN;
    }

    if (userdir_user) {
	apr_uid_t uid = (apr_uid_t) ap_uname2id(userdir_user);
	if (uid == finfo.user) {
	    return HTTP_OK;
	}
    }

    for (i = 0; i < d->owner_uids->nelts; ++i) {
	apr_uid_t uid = ((apr_uid_t *)(d->owner_uids->elts))[i];
	if (uid == finfo.user) {
	    return HTTP_OK;
	}
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		  "allowfileowner_filter: "
		  "File owner %ld not allowed: %s",
		  (long)finfo.user, r->filename);

    return HTTP_FORBIDDEN;
}

static apr_status_t allowfileowner_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e = APR_BRIGADE_FIRST(bb);
    apr_bucket_file *a = e->data;
    int errstatus;

    if (!APR_BUCKET_IS_FILE(e)) {
        return ap_pass_brigade(f->next, bb);
    }

    if ((errstatus = allowfileowner_check(f->r, a->fd)) != HTTP_OK) {
	apr_bucket *e;

	apr_brigade_cleanup(bb);
	e = ap_bucket_error_create(errstatus,
				    NULL, f->r->pool,
				    f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, e);
	e = apr_bucket_eos_create(f->c->bucket_alloc);
	APR_BRIGADE_INSERT_TAIL(bb, e);

	return ap_pass_brigade(f->next, bb);
    }

    return ap_pass_brigade(f->next, bb);
}

static const command_rec module_cmds[] =
{
    AP_INIT_RAW_ARGS("AllowFileOwner", allowfileowner_cmd, NULL, OR_FILEINFO,
                     "A list of user names which content files must be owned by"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(filter_name, allowfileowner_filter,
                              NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA allowfileowner_module =
{
    STANDARD20_MODULE_STUFF,
    create_dir_config,		/* create per-directory config structure */
    NULL,              		/* merge per-directory config structures */
    NULL,         		/* create per-server config structure */
    NULL,              		/* merge per-server config structures */
    module_cmds,		/* command apr_table_t */
    register_hooks     		/* register hooks */
};

