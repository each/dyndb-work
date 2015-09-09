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

#include <dns/types.h>

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

#define DNS_DTTYPE_SQ 0x0001
#define DNS_DTTYPE_SR 0x0002
#define DNS_DTTYPE_CQ 0x0004
#define DNS_DTTYPE_CR 0x0008
#define DNS_DTTYPE_AQ 0x0010
#define DNS_DTTYPE_AR 0x0020
#define DNS_DTTYPE_RQ 0x0040
#define DNS_DTTYPE_RR 0x0080
#define DNS_DTTYPE_FQ 0x0100
#define DNS_DTTYPE_FR 0x0200

#define DNS_DTTYPE_QUERY \
	(DNS_DTTYPE_SQ|DNS_DTTYPE_CQ|DNS_DTTYPE_AQ|DNS_DTTYPE_RQ|DNS_DTTYPE_FQ)
#define DNS_DTTYPE_RESPONSE \
	(DNS_DTTYPE_SR|DNS_DTTYPE_CR|DNS_DTTYPE_AR|DNS_DTTYPE_RR|DNS_DTTYPE_FR)

typedef enum {
	dns_commtype_udp,	 /*% UDP socket */
	dns_commtype_tcp_accept, /*% TCP accept socket */
	dns_commtype_tcp,	 /*% TCP handler socket */
	dns_commtype_local,	 /*% AF_UNIX socket */
	dns_commtype_raw	 /*% Raw - not DNS format */
} dns_commtype_t;

typedef struct dns_dtenv {
	isc_mem_t *mctx;

	struct fstrm_iothr *iothr;
	struct fstrm_iothr_queue *ioq;

	isc_region_t identity;
	isc_region_t version;

	isc_uint16_t msgtypes;
} dns_dtenv_t;

isc_result_t
dns_dt_create(isc_mem_t *mctx, const char *sockpath,
	     unsigned int workers, dns_dtenv_t **envp);

isc_result_t
dns_dt_setidentity(dns_dtenv_t *env, const char *identity);

isc_result_t
dns_dt_setversion(dns_dtenv_t *env, const char *version);

isc_result_t
dns_dt_init(dns_dtenv_t *env);

void
dns_dt_delete(dns_dtenv_t *env);

void
dns_dt_send(dns_dtenv_t *env, dns_dtmsgtype_t msgtype,
	    struct sockaddr_storage *sock, dns_commtype_t commtype,
	    dns_name_t *zone, dns_message_t *message,
	    isc_time_t *qtime, isc_time_t *rtime,
	    isc_buffer_t *buf);

#endif /* _DNSTAP_H */
