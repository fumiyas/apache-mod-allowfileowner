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
 * mod_allowfileowner
 * Copyright (c) 2013 SATOH Fumiyasu @ OSS Technology Corp., Japan
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"
#include "mpm_common.h"
#include "mod_core.h"
#include "util_md5.h"

#include "apr_strings.h"

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

static int allowfileowner_handler(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *e;
    core_dir_config *d;
    int errstatus;
    apr_file_t *fd = NULL;
    apr_status_t status;
    /* XXX if/when somebody writes a content-md5 filter we either need to
     *     remove this support or coordinate when to use the filter vs.
     *     when to use this code
     *     The current choice of when to compute the md5 here matches the 1.3
     *     support fairly closely (unlike 1.3, we don't handle computing md5
     *     when the charset is translated).
     */
    int bld_content_md5;
    allowfileowner_dir_config *d2;
    int i;

    if (strcmp(r->handler,"allowfileowner")) {
        return DECLINED;
    }

    d = (core_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &core_module);
    d2 = (allowfileowner_dir_config *)ap_get_module_config(r->per_dir_config,
                                                &allowfileowner_module);
    bld_content_md5 = (d->content_md5 & 1)
                      && r->output_filters->frec->ftype != AP_FTYPE_RESOURCE;

    ap_allow_standard_methods(r, MERGE_ALLOW, M_GET, M_OPTIONS, M_POST, -1);

    /* If filters intend to consume the request body, they must
     * register an InputFilter to slurp the contents of the POST
     * data from the POST input stream.  It no longer exists when
     * the output filters are invoked by the default handler.
     */
    if ((errstatus = ap_discard_request_body(r)) != OK) {
        return errstatus;
    }

    if (r->method_number == M_GET || r->method_number == M_POST) {
        if (r->finfo.filetype == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "File does not exist: %s", r->filename);
            return HTTP_NOT_FOUND;
        }

        /* Don't try to serve a dir.  Some OSs do weird things with
         * raw I/O on a dir.
         */
        if (r->finfo.filetype == APR_DIR) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Attempt to serve directory: %s", r->filename);
            return HTTP_NOT_FOUND;
        }

        if ((r->used_path_info != AP_REQ_ACCEPT_PATH_INFO) &&
            r->path_info && *r->path_info)
        {
            /* default to reject */
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "File does not exist: %s",
                          apr_pstrcat(r->pool, r->filename, r->path_info, NULL));
            return HTTP_NOT_FOUND;
        }

        /* We understood the (non-GET) method, but it might not be legal for
           this particular resource. Check to see if the 'deliver_script'
           flag is set. If so, then we go ahead and deliver the file since
           it isn't really content (only GET normally returns content).

           Note: based on logic further above, the only possible non-GET
           method at this point is POST. In the future, we should enable
           script delivery for all methods.  */
        if (r->method_number != M_GET) {
            core_request_config *req_cfg;

            req_cfg = ap_get_module_config(r->request_config, &core_module);
            if (!req_cfg->deliver_script) {
                /* The flag hasn't been set for this request. Punt. */
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "This resource does not accept the %s method.",
                              r->method);
                return HTTP_METHOD_NOT_ALLOWED;
            }
        }


        if ((status = apr_file_open(&fd, r->filename, APR_READ | APR_BINARY
#if APR_HAS_SENDFILE
                            | ((d->enable_sendfile == ENABLE_SENDFILE_OFF)
                                                ? 0 : APR_SENDFILE_ENABLED)
#endif
                                    , 0, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
                          "file permissions deny server access: %s", r->filename);
            return HTTP_FORBIDDEN;
        }

	if (d2->owner_uids->nelts) {
	    int uid_found = 0;
	    apr_finfo_t finfo;

	    status = apr_file_info_get(&finfo, APR_FINFO_OWNER, fd);
	    if (status != APR_SUCCESS) {
		/* FIXME */
	    }

	    for (i = 0; i < d2->owner_uids->nelts; ++i) {
		apr_uid_t uid = ((apr_uid_t *)(d2->owner_uids->elts))[i];
		if (uid == finfo.user) {
		    uid_found = 1;
		    break;
		}
	    }

	    if (!uid_found) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
			      "allowfileowner_handler: "
			      "Invalid file owner %ld"
			      ": %s",
			      (long)finfo.user,
			      r->filename);
		return HTTP_FORBIDDEN;
	    }
	}

        ap_update_mtime(r, r->finfo.mtime);
        ap_set_last_modified(r);
        ap_set_etag(r);
        ap_set_accept_ranges(r);
        ap_set_content_length(r, r->finfo.size);

        bb = apr_brigade_create(r->pool, c->bucket_alloc);

        if ((errstatus = ap_meets_conditions(r)) != OK) {
            apr_file_close(fd);
            r->status = errstatus;
        }
        else {
            if (bld_content_md5) {
                apr_table_setn(r->headers_out, "Content-MD5",
                               ap_md5digest(r->pool, fd));
            }

            /* For platforms where the size of the file may be larger than
             * that which can be stored in a single bucket (where the
             * length field is an apr_size_t), split it into several
             * buckets: */
            if (sizeof(apr_off_t) > sizeof(apr_size_t)
                && r->finfo.size > AP_MAX_SENDFILE) {
                apr_off_t fsize = r->finfo.size;
                e = apr_bucket_file_create(fd, 0, AP_MAX_SENDFILE, r->pool,
                                           c->bucket_alloc);
                while (fsize > AP_MAX_SENDFILE) {
                    apr_bucket *ce;
                    apr_bucket_copy(e, &ce);
                    APR_BRIGADE_INSERT_TAIL(bb, ce);
                    e->start += AP_MAX_SENDFILE;
                    fsize -= AP_MAX_SENDFILE;
                }
                e->length = (apr_size_t)fsize; /* Resize just the last bucket */
            }
            else {
                e = apr_bucket_file_create(fd, 0, (apr_size_t)r->finfo.size,
                                           r->pool, c->bucket_alloc);
            }

#if APR_HAS_MMAP
            if (d->enable_mmap == ENABLE_MMAP_OFF) {
                (void)apr_bucket_file_enable_mmap(e, 0);
            }
#endif
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }

        e = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);

        status = ap_pass_brigade(r->output_filters, bb);
        if (status == APR_SUCCESS
            || r->status != HTTP_OK
            || c->aborted) {
            return OK;
        }
        else {
            /* no way to know what type of error occurred */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r,
                          "allowfileowner_handler: ap_pass_brigade returned %i",
                          status);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else {              /* unusual method (not GET or POST) */
        if (r->method_number == M_INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Invalid method in request %s", r->the_request);
            return HTTP_NOT_IMPLEMENTED;
        }

        if (r->method_number == M_OPTIONS) {
            return ap_send_http_options(r);
        }
        return HTTP_METHOD_NOT_ALLOWED;
    }
}

static const command_rec module_cmds[] =
{
    AP_INIT_RAW_ARGS("AllowFileOwner", allowfileowner_cmd, NULL, OR_FILEINFO,
                     "FIXME"),
    {NULL}
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(allowfileowner_handler,NULL,NULL,APR_HOOK_LAST);
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

