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


#include <config.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/region.h>
#include <isc/task.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/dyndb.h>
#include <dns/log.h>
#include <dns/types.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <string.h>

#if HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)


typedef struct dyndb_implementation dyndb_implementation_t;
struct dyndb_implementation {
	isc_mem_t			*mctx;
	void				*handle;
	dns_dyndb_register_t		*register_func;
	dns_dyndb_destroy_t		*destroy_func;
	LINK(dyndb_implementation_t)	link;
};

/* List of implementations. Locked by dyndb_lock. */
static LIST(dyndb_implementation_t) dyndb_implementations;

/* Locks dyndb_implementations. */
static isc_mutex_t dyndb_lock;
static isc_once_t once = ISC_ONCE_INIT;

static void
dyndb_initialize(void) {
	RUNTIME_CHECK(isc_mutex_init(&dyndb_lock) == ISC_R_SUCCESS);
	INIT_LIST(dyndb_implementations);
}

#if HAVE_DLFCN_H
static isc_result_t
load_symbol(void *handle, const char *filename,
	    const char *symbol_name, void **symbolp)
{
	const char *errmsg;
	void *symbol;

	REQUIRE(handle != NULL);
	REQUIRE(symbolp != NULL && *symbolp == NULL);

	symbol = dlsym(handle, symbol_name);
	if (symbol == NULL) {
		errmsg = dlerror();
		if (errmsg == NULL)
			errmsg = "returned function pointer is NULL";
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DYNDB, ISC_LOG_ERROR,
			      "failed to lookup symbol %s in "
			      "dyndb module '%s': %s",
			      symbol_name, filename, errmsg);
		return (ISC_R_FAILURE);
	}
	dlerror();

	*symbolp = symbol;

	return (ISC_R_SUCCESS);
}

static isc_result_t
load_library(isc_mem_t *mctx, const char *filename,
	     const dns_dyndbctx_t *args,
	     dyndb_implementation_t **impp)
{
	isc_result_t result;
	size_t module_size;
	isc_buffer_t *module_buf = NULL;
	isc_region_t module_region;
	void *handle = NULL;
	dyndb_implementation_t *imp;
	dns_dyndb_register_t *register_func = NULL;
	dns_dyndb_destroy_t *destroy_func = NULL;
	dns_dyndb_version_t *version_func = NULL;
	int version, flags;

	REQUIRE(args != NULL);
	REQUIRE(impp != NULL && *impp == NULL);

	/* Build up the full path. */
	module_size = strlen(filename) + 1;

	CHECK(isc_buffer_allocate(mctx, &module_buf, module_size));
	isc_buffer_putstr(module_buf, filename);
	isc_buffer_putuint8(module_buf, 0);
	isc_buffer_region(module_buf, &module_region);

	flags = RTLD_NOW|RTLD_GLOBAL;
#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	handle = dlopen((char *)module_region.base, flags);
	if (handle == NULL) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	CHECK(load_symbol(handle, filename, "dyndb_init",
			  (void **)&register_func));
	CHECK(load_symbol(handle, filename, "dyndb_destroy",
			  (void **)&destroy_func));
	CHECK(load_symbol(handle, filename, "dyndb_version",
			  (void **)&version_func));

	version = version_func(NULL);
	if (version < (DNS_DYNDB_VERSION - DNS_DYNDB_AGE) ||
	    version > DNS_DYNDB_VERSION)
	{
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DYNDB, ISC_LOG_ERROR,
			      "driver API version mismatch: %d/%d",
			      version, DNS_DYNDB_VERSION);
		CHECK(ISC_R_FAILURE);
	}


	imp = isc_mem_get(mctx, sizeof(dyndb_implementation_t));
	if (imp == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	imp->mctx = NULL;
	isc_mem_attach(mctx, &imp->mctx);
	imp->handle = handle;
	imp->register_func = register_func;
	imp->destroy_func = destroy_func;
	INIT_LINK(imp, link);

	*impp = imp;

cleanup:
	if (result != ISC_R_SUCCESS)
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE,
			      DNS_LOGMODULE_DYNDB, ISC_LOG_ERROR,
			      "failed to dynamically load driver '%s': %s",
			      filename, dlerror());
	if (result != ISC_R_SUCCESS && handle != NULL)
		dlclose(handle);
	if (module_buf != NULL)
		isc_buffer_free(&module_buf);

	return (result);
}

static void
unload_library(dyndb_implementation_t **impp) {
	dyndb_implementation_t *imp;

	REQUIRE(impp != NULL && *impp != NULL);

	imp = *impp;

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(dyndb_implementation_t));

	*impp = NULL;
}
#else	/* HAVE_DLFCN_H */
static isc_result_t
load_library(isc_mem_t *mctx, const char *filename,
	     dyndb_implementation_t **impp)
{
	UNUSED(mctx);
	UNUSED(filename);
	UNUSED(impp);

	isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
		      ISC_LOG_ERROR,
		      "dynamic database support is not implemented")

	return (ISC_R_NOTIMPLEMENTED);
}

static void
unload_library(dyndb_implementation_t **impp)
{
	dyndb_implementation_t *imp;

	REQUIRE(impp != NULL && *impp != NULL);

	imp = *impp;

	isc_mem_putanddetach(&imp->mctx, imp, sizeof(dyndb_implementation_t));

	*impp = NULL;
}
#endif	/* HAVE_DLFCN_H */

isc_result_t
dns_dyndb_load(const char *libname, const char *name, const char *parameters,
	       isc_mem_t *mctx, const dns_dyndbctx_t *dctx)
{
	isc_result_t result;
	dyndb_implementation_t *implementation = NULL;

	REQUIRE(DNS_DYNDBCTX_VALID(dctx));

	RUNTIME_CHECK(isc_once_do(&once, dyndb_initialize) == ISC_R_SUCCESS);

	CHECK(load_library(mctx, libname, dctx, &implementation));
	CHECK(implementation->register_func(mctx, name, parameters, dctx));

	LOCK(&dyndb_lock);
	APPEND(dyndb_implementations, implementation, link);
	UNLOCK(&dyndb_lock);

	return (ISC_R_SUCCESS);

cleanup:
	if (implementation != NULL)
		unload_library(&implementation);

	return (result);
}

void
dns_dyndb_cleanup(isc_boolean_t exiting) {
	dyndb_implementation_t *elem;
	dyndb_implementation_t *prev;

	RUNTIME_CHECK(isc_once_do(&once, dyndb_initialize) == ISC_R_SUCCESS);

	LOCK(&dyndb_lock);
	elem = TAIL(dyndb_implementations);
	while (elem != NULL) {
		prev = PREV(elem, link);
		UNLINK(dyndb_implementations, elem, link);
		elem->destroy_func();
		unload_library(&elem);
		elem = prev;
	}
	UNLOCK(&dyndb_lock);

	if (exiting == ISC_TRUE)
		isc_mutex_destroy(&dyndb_lock);
}

isc_result_t
dns_dyndb_createctx(isc_mem_t *mctx, isc_hash_t *hctx, isc_log_t *lctx,
		    dns_view_t *view, dns_zonemgr_t *zmgr,
		    isc_task_t *task, isc_timermgr_t *tmgr,
		    dns_dyndbctx_t **dctxp) {
	dns_dyndbctx_t *dctx;

	REQUIRE(dctxp != NULL && *dctxp == NULL);

	dctx = isc_mem_get(mctx, sizeof(*dctx));
	if (dctx == NULL)
		return (ISC_R_NOMEMORY);

	memset(dctx, 0, sizeof(*dctx));
	if (view != NULL)
		dns_view_attach(view, &dctx->view);
	if (zmgr != NULL)
		dns_zonemgr_attach(zmgr, &dctx->zmgr);
	if (task != NULL)
		isc_task_attach(task, &dctx->task);
	dctx->timermgr = tmgr;
	dctx->hctx = hctx;
	dctx->lctx = lctx;

	isc_mem_attach(mctx, &dctx->mctx);
	dctx->magic = DNS_DYNDBCTX_MAGIC;

	*dctxp = dctx;

	return (ISC_R_SUCCESS);
}

void
dns_dyndb_destroyctx(dns_dyndbctx_t **dctxp) {
	dns_dyndbctx_t *dctx;

	REQUIRE(dctxp != NULL && DNS_DYNDBCTX_VALID(*dctxp));

	dctx = *dctxp;
	if (dctxp == NULL)
		return;

	dctx->magic = 0;

	if (dctx->view != NULL)
		dns_view_detach(&dctx->view);
	if (dctx->zmgr != NULL)
		dns_zonemgr_detach(&dctx->zmgr);
	if (dctx->task != NULL)
		isc_task_detach(&dctx->task);
	dctx->timermgr = NULL;
	dctx->lctx = NULL;

	isc_mem_putanddetach(&dctx->mctx, dctx, sizeof(*dctx));

	*dctxp = NULL;
}
