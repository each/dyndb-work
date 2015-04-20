/*
 * Copyright (C) 2008-2011  Red Hat, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND Red Hat DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL Red Hat BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */


#ifndef DNS_DYNDB_H
#define DNS_DYNDB_H

#include <isc/types.h>

#include <dns/types.h>

ISC_LANG_BEGINDECLS

/*!
 * \brief
 * Context for intializing a dyndb module.
 *
 * This structure passes pointers to globals to which a dyndb
 * module will need access -- the server memory context, hash
 * context, log context, etc.  The structure doesn't persist
 * beyond configuring the dyndb module. The module's register function
 * should attach to all reference-counted variables and its destroy
 * function should detach from them.
 */
struct dns_dyndbctx {
	unsigned int	magic;
	isc_mem_t	*mctx;
	isc_hash_t	*hctx;
	isc_log_t	*lctx;
	dns_view_t	*view;
	dns_zonemgr_t	*zmgr;
	isc_task_t	*task;
	isc_timermgr_t	*timermgr;
};

#define DNS_DYNDBCTX_MAGIC	ISC_MAGIC('D', 'd', 'b', 'c')
#define DNS_DYNDBCTX_VALID(d)	ISC_MAGIC_VALID(d, DNS_DYNDBCTX_MAGIC)

/*
 * API version
 *
 * When the API changes, increment DNS_DYNDB_VERSION. If the
 * change is backward-compatible (e.g., adding a new function call
 * but not changing or removing an old one), increment DNS_DYNDB_AGE;
 * if not, set DNS_DYNDB_AGE to 0.
 */
#ifndef DNS_DYNDB_VERSION
#define DNS_DYNDB_VERSION 1
#define DNS_DYNDB_AGE 0
#endif

typedef isc_result_t dns_dyndb_register_t(isc_mem_t *mctx,
					  const char *name,
					  const char *parameters,
					  const dns_dyndbctx_t *dctx);
/*%
 * Register a new driver instance. 'name' should generally be unique.
 * 'parameters' contains the driver configuration text. 'dctx' is the
 * initialization context.
 */

typedef void dns_dyndb_destroy_t(void);
/*%
 * Destroy a driver instance. Dereference any reference-counted
 * variables passed in via 'dctx' in the register function.
 */

typedef int dns_dyndb_version_t(unsigned int *flags);
/*%
 * Return the API version number this module was compiled with.
 */

isc_result_t
dns_dyndb_load(const char *libname, const char *name, const char *parameters,
	       isc_mem_t *mctx, const dns_dyndbctx_t *dctx);
/*%
 * Load a dyndb module.
 */

void
dns_dyndb_cleanup(isc_boolean_t exiting);
/*%
 * Shut down and destroy all running dyndb modules
 */

isc_result_t
dns_dyndb_createctx(isc_mem_t *mctx, isc_hash_t *hctx, isc_log_t *lctx,
		    dns_view_t *view, dns_zonemgr_t *zmgr,
		    isc_task_t *task, isc_timermgr_t *tmgr,
		    dns_dyndbctx_t **dctxp);

void
dns_dyndb_destroyctx(dns_dyndbctx_t **dctxp);
/*%
 * Create/destroy a dyndb context structure.
 */

ISC_LANG_ENDDECLS

#endif /* DNS_DYNDB_H */
