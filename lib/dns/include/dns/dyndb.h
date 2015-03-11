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

struct dns_dyndbctx {
	unsigned int	magic;
	isc_mem_t	*mctx;
	dns_view_t	*view;
	dns_zonemgr_t	*zmgr;
	isc_task_t	*task;
	isc_timermgr_t	*timermgr;
};

#define DNS_DYNDBCTX_MAGIC	ISC_MAGIC('D', 'd', 'b', 'c')
#define DNS_DYNDBCTX_VALID(d)	ISC_MAGIC_VALID(d, DNS_DYNDBCTX_MAGIC)

typedef isc_result_t (*dns_dyndb_register_t)(isc_mem_t *mctx,
					     const char *name,
					     const char * const *argv,
					     const dns_dyndbctx_t *dctx);
typedef void (*dns_dyndb_destroy_t)(void);

/*
 * TODO:
 * Add annotated comments.
 */

isc_result_t
dns_dyndb_load(const char *libname, const char *name,
	       isc_mem_t *mctx, const char * const *argv,
	       const dns_dyndbctx_t *dctx);

void
dns_dyndb_cleanup(isc_boolean_t exiting);

isc_result_t
dns_dyndb_createctx(isc_mem_t *mctx, dns_view_t *view,
		    dns_zonemgr_t *zmgr, isc_task_t *task,
		    isc_timermgr_t *tmgr, dns_dyndbctx_t **dctxp);

void
dns_dyndb_destroyctx(dns_dyndbctx_t **dctxp);

ISC_LANG_ENDDECLS

#endif /* DNS_DYNDB_H */
