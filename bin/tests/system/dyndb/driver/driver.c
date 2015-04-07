/*
 * Driver API implementation and main entry point for BIND.
 *
 * BIND calls dyndb_verison() before loading, dyndb_init() during startup
 * and dyndb_destroy() during shutdown.
 *
 * It is completely up to implementation what to do.
 *
 * dynamic-db "name" {} sections in named.conf are independent so driver init()
 * and destroy() functions are called independently for each section even
 * if they reference the same driver/library. It is up to driver implementation
 * to detect and catch this situation if it is undesirable.
 *
 * Copyright (C) 2009-2015  Red Hat ; see COPYING for license
 */

#include <config.h>

#include <isc/commandline.h>
#include <isc/hash.h>
#include <isc/mem.h>
#include <isc/lib.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dyndb.h>
#include <dns/lib.h>
#include <dns/types.h>

#include "db.h"
#include "log.h"
#include "instance_manager.h"

static dns_dbimplementation_t *sampledb_imp;
const char *impname = "dynamic-sample";

dns_dyndb_destroy_t dyndb_destroy;
dns_dyndb_register_t dyndb_init;
dns_dyndb_version_t dyndb_version;

/*
 * Driver init is is called once during startup and then on every reload.
 *
 * @code
 * dyndb example-name "sample.so" { param1 param2 };
 * @endcode
 * 
 * @param[in] name User-defined string from dynamic-db "name" {}; definition
 *                 in named.conf.
 *                 The example above will have name = "example-name".
 * @param[in] argc Number of arg parameters
 *                 definition. The example above will have
 *                 argc = 2;
 * @param[in] argv User-defined strings from arg parameters in dynamic-db
 *                 definition. The example above will have
 *                 argv[0] = "param1";
 *                 argv[1] = "param2";
 */
isc_result_t
dyndb_init(isc_mem_t *mctx, const char *name, const char *parameters,
	   const dns_dyndbctx_t *dctx)
{
	isc_result_t result;
	dns_dbimplementation_t *sampledb_imp_new = NULL;
	unsigned int argc;
	isc_boolean_t inithash = ISC_FALSE;
	char **argv = NULL;
	char *s = NULL;

	REQUIRE(name != NULL);
	REQUIRE(dctx != NULL);

	isc_lib_register();
	dns_lib_init();
	isc_log_setcontext(dctx->lctx);
	dns_log_setcontext(dctx->lctx);

	if (isc_hashctx == NULL) {
		isc_hash_ctxattach(dctx->hctx, &isc_hashctx);
		inithash = ISC_TRUE;
	}

	log_info("registering dynamic sample driver for instance '%s'", name);

	/* Register new DNS DB implementation. */
	result = dns_db_register(impname, create_db, NULL, mctx,
				 &sampledb_imp_new);
	if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS)
		return (result);
	else if (result == ISC_R_SUCCESS)
		sampledb_imp = sampledb_imp_new;

	s = isc_mem_strdup(mctx, parameters);
	if (s == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	result = isc_commandline_strtoargv(mctx, s, &argc, &argv, 0);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/* Finally, create the instance. */
	result = manager_create_db_instance(mctx, name, argc, argv, dctx);

 cleanup:
	if (result != ISC_R_SUCCESS && inithash)
		isc_hash_ctxdetach(&isc_hashctx);

	if (s != NULL)
		isc_mem_free(mctx, s);
	if (argv != NULL)
		isc_mem_put(mctx, argv, argc * sizeof(*argv));

	return (result);
}

/*
 * Driver destroy is called on every reload and then once during shutdown.
 *
 * @warning
 * It is also called for every dynamic-db section in named.conf but there is no
 * way how to find out for which instance.
 */
void
dyndb_destroy(void) {
	/* Only unregister the implementation if it was registered by us. */
	if (sampledb_imp != NULL)
		dns_db_unregister(&sampledb_imp);

	destroy_manager();
	isc_hash_ctxdetach(&isc_hashctx);
}

/*
 * Driver version is called when loading the driver to ensure there
 * is no API mismatch betwen the driver and the caller.
 */
int
dyndb_version(unsigned int *flags) {
	UNUSED(flags);

	return (DNS_DYNDB_VERSION);
}
