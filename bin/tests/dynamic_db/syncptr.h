/*
 * syncptr.h
 *
 *  Created on: Mar 9, 2015
 *      Author: pspacek
 */

#ifndef SYNCPTR_H_
#define SYNCPTR_H_

#include <dns/diff.h>
isc_result_t
syncptrs(sample_instance_t *inst, dns_name_t *name, dns_rdataset_t *rdataset,
	 dns_diffop_t op);

#endif /* SYNCPTR_H_ */
