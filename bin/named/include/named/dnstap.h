/*
 * Copyright (C) 2015  Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _DNSTAP_H
#define _DNSTAP_H

#ifdef DNSTAP
#include <fstrm.h>
#include <protobuf-c/protobuf-c.h>
#endif /* DNSTAP */

#include <isc/region.h>
#include <isc/types.h>

/*%
 * Dnstap message types:
 *
 * STUB QUERY: SQ
 * STUB RESPONSE: SR
 * CLIENT QUERY: CQ
 * CLIENT RESPONSE: CR
 * AUTH QUERY: AQ
 * AUTH RESPONSE: AR
 * RESOLVER QUERY: RQ
 * RESOLVER RESPONSE: RR
 * FORWARDER QUERY: FQ
 * FORWARDER RESPONSE: FR
 */

#define NS_DTTYPE_SQ 0x0001
#define NS_DTTYPE_SR 0x0002
#define NS_DTTYPE_CQ 0x0004
#define NS_DTTYPE_CR 0x0008
#define NS_DTTYPE_AQ 0x0010
#define NS_DTTYPE_AR 0x0020
#define NS_DTTYPE_RQ 0x0040
#define NS_DTTYPE_RR 0x0080
#define NS_DTTYPE_FQ 0x0100
#define NS_DTTYPE_FR 0x0200

typedef isc_uint16_t ns_dtmsgtype_t;

typedef enum ns_commtype_t {
	ns_commtype_udp,	/*% UDP socket */
	ns_commtype_tcp_accept, /*% TCP accept socket */
	ns_commtype_tcp,	/*% TCP handler socket */
	ns_commtype_local,	/*% AF_UNIX socket */
	ns_commtype_raw		/*% Raw - not DNS format */
};

typedef struct ns_dtenv {
	struct fstrm_iothr *iothr;
	struct fstrm_iothr_queue *ioq;

	isc_textregion_t *identity;
	isc_textregion_t *version;

	isc_uint16_t msgtypes;
} ns_dtenv_t;

isc_result_t
ns_dt_create(const char *sockpath, unsigned int workers, ns_dtenv_t **envp);

isc_result_t
ns_dt_init(ns_dtenv_t *env);

void
ns_dt_delete(ns_dtenv_t *env);

void
ns_dt_send(ns_dtenv_t *env, ns_dtmsgtype_t msgtype,
	   struct sockaddr_storage *sock, ns_commtype_t commtype,
	   dns_name_t *zone, dns_message_t *message,
	   isc_time_t *qtime, isc_time_t *rtime,
	   isc_buffer_t *buf);

#endif /* _DNSTAP_H */
