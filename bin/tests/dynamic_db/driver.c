/*
 * Driver API implementation and main entry point for BIND.
 *
 * BIND calls dynamic_driver_init() during startup
 * and dynamic_driver_destroy() during shutdown.
 *
 * It is completely up to implementation what to do.
 *
 * dynamic-db "name" {} sections in named.conf are independent so driver init()
 * and destroy() functions are called independently for each section even
 * if they reference the same driver/library. It is up to driver implementation
 * to detect and catch this situation if it is undesirable.
 *
 * Copyright (C) 2009--2015  Red Hat ; see COPYING for license
 */

#include <isc/hash.h>
#include <isc/lib.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dyndb.h>
#include <dns/types.h>

#include "db.h"
#include "log.h"
#include "instance_manager.h"

static dns_dbimplementation_t *sampledb_imp;
const char *impname = "dynamic-sample";

dns_dyndb_destroy_t driver_destroy;
dns_dyndb_register_t driver_init;

/*
 * Driver init is is called once during startup and then on every reload.
 *
 * @code
 * dynamic-db "example-name" {
 * 	arg "sample.so";
 * 	arg "param1";
 * 	arg "param2";
 * };
 * @endcode
 * 
 * @param[in] name User-defined string from dynamic-db "name" {}; definition
 *                 in named.conf.
 *                 The example above will have name = "example-name".
 * @param[in] argv User-defined strings from arg parameters in dynamic-db
 *                 definition. The example above will have
 *                 argv[0] = "param1";
 *                 argv[1] = "param2";
 */
isc_result_t
dynamic_driver_init(isc_mem_t *mctx, const char *name,
		    const char * const *argv, dns_dyndbctx_t *dctx)
{
	dns_dbimplementation_t *sampledb_imp_new = NULL;
	isc_result_t result;

	REQUIRE(name != NULL);
	REQUIRE(argv != NULL);
	REQUIRE(dctx != NULL);

	isc_lib_register();
	isc_hash_create(mctx, NULL, DNS_NAME_MAXWIRE);

	log_info("registering dynamic sample driver for instance '%s'", name);

	/* Register new DNS DB implementation. */
	result = dns_db_register(impname, create_db, NULL, mctx,
				 &sampledb_imp_new);
	if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS)
		return (result);
	else if (result == ISC_R_SUCCESS)
		sampledb_imp = sampledb_imp_new;

	/* Finally, create the instance. */
	result = manager_create_db_instance(mctx, name, argv, dctx);

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
dynamic_driver_destroy(void) {
	/* Only unregister the implementation if it was registered by us. */
	if (sampledb_imp != NULL)
		dns_db_unregister(&sampledb_imp);

	destroy_manager();
	isc_hash_destroy();
}
