/**
 * Driver instance manager.
 *
 * Copyright (C) 2009--2015  Red Hat ; see COPYING for license
 */

#ifndef _LD_INST_MANAGER_H_
#define _LD_INST_MANAGER_H_

#include <dns/types.h>

#include "instance.h"

typedef struct db_instance db_instance_t;

void destroy_manager(void);

isc_result_t
manager_create_db_instance(isc_mem_t *mctx, const char *name,
			   const char * const *argv,
			   dns_dyndb_arguments_t *dyndb_args);

isc_result_t
manager_get_sample_instance(const char *name, sample_instance_t **inst);

#endif /* !_LD_INST_MANAGER_H_ */
