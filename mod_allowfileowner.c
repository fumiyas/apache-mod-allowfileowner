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
 * Copyright (c) 2013-2014 SATOH Fumiyasu @ OSS Technology Corp., Japan
 *
 * Development home: <https://github.com/fumiyas/apache-mod-allowfileowner>
 * Author's home: <https://fumiyas.github.io/>
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "util_filter.h"

static const char filter_name[] = "ALLOWFILEOWNER";

module AP_MODULE_DECLARE_DATA allowfileowner_module;

typedef struct {
    apr_array_header_t *owner_uids;
    apr_array_header_t *owner_gids;
    int userdir;
} allowfileowner_dir_config;

static void *create_dir_config(apr_pool_t *p, char *d)
{
    allowfileowner_dir_config *conf = apr_pcalloc(p, sizeof(*conf));

    conf->owner_uids = apr_array_make(p, 1, sizeof(apr_uid_t));
    conf->owner_gids = apr_array_make(p, 1, sizeof(apr_gid_t));
    conf->userdir = 0;

    return conf;
}

static const char *allowfileowner_cmd(cmd_parms *cmd, void *in_conf,
                                      const char *args)
{
    allowfileowner_dir_config *conf = in_conf;
    const char *username;
    apr_uid_t uid, *uidp;
    apr_gid_t gid;

    while (*args) {
        username = ap_getword_conf(cmd->pool, &args);
	if (apr_uid_get(&uid, &gid, username, cmd->pool) == APR_SUCCESS) {
	    uidp = (apr_uid_t *) apr_array_push(conf->owner_uids);
	    *uidp = uid;
	}
    }

    return NULL;
}

static const char *allowfileownergroup_cmd(cmd_parms *cmd, void *in_conf,
                                      const char *args)
{
    allowfileowner_dir_config *conf = in_conf;
    const char *groupname;
    apr_gid_t gid, *gidp;

    while (*args) {
        groupname = ap_getword_conf(cmd->pool, &args);
	if (apr_gid_get(&gid, groupname, cmd->pool) == APR_SUCCESS) {
	    gidp = (apr_gid_t *) apr_array_push(conf->owner_gids);
	    *gidp = gid;
	}
    }

    return NULL;
}

static int allowfileowner_check(request_rec *r, apr_file_t *fd)
{
    allowfileowner_dir_config *d;
    const char *userdir_user = NULL;
    apr_finfo_t finfo;
    apr_status_t status;
    int i;

    d = (allowfileowner_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &allowfileowner_module);
    if (d->userdir) {
	apr_table_t *notes = r->main ? r->main->notes : r->notes;
	userdir_user = apr_table_get(notes, "mod_userdir_user");
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		  "allowfileowner: "
		  "%s userdir_user=%s, "
		  "owner_uids->nelts=%d: "
		  "owner_gids->nelts=%d: "
		  "%s",
		  (r->main ? "subreq" : "main"),
		  (userdir_user ? userdir_user : "(null)"),
		  d->owner_uids->nelts,
		  d->owner_gids->nelts,
		  r->filename);

    if (!d->owner_uids->nelts && !d->owner_gids->nelts && !userdir_user) {
	return HTTP_OK;
    }

    status = apr_file_info_get(&finfo, APR_FINFO_OWNER, fd);
    if (status != APR_SUCCESS) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
		      "allowfileowner: "
		      "apr_file_info_get() failed: %s",
		      r->filename);
	return HTTP_FORBIDDEN;
    }

    if (d->userdir && userdir_user) {
	apr_uid_t uid;
	apr_gid_t gid;

	if (apr_uid_get(&uid, &gid, userdir_user, r->pool) == APR_SUCCESS
	    && uid == finfo.user) {
	    return HTTP_OK;
	}
    }

    for (i = 0; i < d->owner_uids->nelts; ++i) {
	apr_uid_t uid = ((apr_uid_t *)(d->owner_uids->elts))[i];
	if (uid == finfo.user) {
	    return HTTP_OK;
	}
    }

    for (i = 0; i < d->owner_gids->nelts; ++i) {
	apr_gid_t gid = ((apr_gid_t *)(d->owner_gids->elts))[i];
	if (gid == finfo.group) {
	    return HTTP_OK;
	}
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		  "allowfileowner: "
		  "File owner:group %ld:%ld not allowed: %s",
		  (long)finfo.user, (long)finfo.group, r->filename);

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
    AP_INIT_RAW_ARGS("AllowFileOwner", allowfileowner_cmd,
		     NULL, OR_FILEINFO,
                     "A list of user names which content files must be owned by"),
    AP_INIT_RAW_ARGS("AllowFileOwnerGroup", allowfileownergroup_cmd,
		     NULL, OR_FILEINFO,
                     "A list of group names which content files must be owned by"),
    AP_INIT_FLAG("AllowFileOwnerInUserDir", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(allowfileowner_dir_config, userdir),
                 OR_FILEINFO,
                 "Set to 'On' to allow static contents files under user's "
		 "directory to be owned by the user"),
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

