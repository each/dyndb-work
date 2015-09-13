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

/*****
 ***** Module Info
 *****/

/*! \file
 * \brief
 * The dt (dnstap) module provides fast passive logging of DNS messages.
 * It uses a lightweight framing on top of event payloads encoded using
 * Protocol Buffers.  The protobuf schema for Dnstap messages is in the
 * file dnstap.proto, which is compiled to dnstap.pb-c.c and dnstap.pb-c.h.
 */

#ifdef DNSTAP
#include <fstrm.h>
#include <protobuf-c/protobuf-c.h>
#endif /* DNSTAP */

#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/sockaddr.h>
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

typedef struct dns_dtenv {
	unsigned int magic;
	isc_refcount_t refcount;

	isc_mem_t *mctx;
	char *socket_path;

	struct fstrm_iothr *iothr;

	isc_region_t identity;
	isc_region_t version;
} dns_dtenv_t;

isc_result_t
dns_dt_create(isc_mem_t *mctx, const char *path,
	     unsigned int workers, dns_dtenv_t **envp);
/*%<
 * Create and initialize the dnstap environment.
 *
 * There should be a single global dnstap environment for the server;
 * copies of it will be attached to each view.
 *
 * Notes:
 *
 *\li	'path' refers to a UNIX domain socket by default. It may 
 *	optionally be prepended with "socket:" or "file:". If prepended
 *	with "file:", then dnstap logs are sent to a file instead of a
 *	socket.
 *
 *\li	This creates an I/O thread in libfstrm, and prepares
 *	'workers' input queues. 'workers' MUST be equal to the number
 *	of worker threads in named; if it's more, some queues will be
 *	wasted and if it's less, some threads will have no queue and
 *	will not log any dnstap events.
 *
 *
 * Requires:
 *
 *\li	'mctx' is a valid memory context.
 *
 *\li	'path' is a valid C string.
 *
 *\li	envp != NULL && *envp == NULL
 *
 * Returns:
 *
 *\li	#ISC_R_SUCCESS
 *\li	#ISC_R_NOMEMORY
 *
 *\li	Other errors are possible.
 */

isc_result_t
dns_dt_setidentity(dns_dtenv_t *env, const char *identity);
isc_result_t
dns_dt_setversion(dns_dtenv_t *env, const char *version);
/*%<
 * Set the "identity" and "version" strings to be sent in dnstap messages.
 *
 * Requires:
 *
 *\li	'env' is a valid dnstap environment.
 */

void
dns_dt_attach(dns_dtenv_t *source, dns_dtenv_t **destp);
/*%<
 * Attach '*destp' to 'source', incrementing the reference counter.
 *
 * Requires:
 *
 *\li	'source' is a valid dnstap environment.
 *
 *\li	'destp' is not NULL and '*destp' is NULL.
 *
 *\li	*destp is attached to source.
 */

void
dns_dt_detach(dns_dtenv_t **envp);
/*%<
 * Detach '*envp', decrementing the reference counter.
 *
 * Requires:
 *
 *\li	'*envp' is a valid dnstap environment.
 *
 * Ensures:
 *
 *\li	'*envp' will be destroyed when the number of references reaches zero.
 *
 *\li	'*envp' is NULL.
 */

void
dns_dt_shutdown(void);
/*%<
 * Shuts down dnstap and frees global resources. This function must only
 * be called immediately before server shutdown.
 */

void
dns_dt_send(dns_view_t *view, dns_dtmsgtype_t msgtype,
	    isc_sockaddr_t *sa, isc_boolean_t tcp, isc_region_t *zone,
	    isc_time_t *qtime, isc_time_t *rtime, isc_buffer_t *buf);
/*%<
 * Sends a dnstap message to the log, if 'msgtype' is one of the message
 * types represented in 'view->dttypes'.
 *
 * Parameters are: 'sa' (address of the peer in the DNS transaction being
 * logged); 'tcp' (boolean indicating whether the transaction was over
 * TCP); 'zone' (the authoritative zone or bailiwick, in uncompressed
 * wire format), 'qtime' and 'rtime' (query and response times; if
 * NULL, they are set to the current time); and 'buf' (the DNS message
 * being logged, in wire format).
 *
 * Requires:
 *
 *\li	'view' is a valid view, and 'view->dtenv' is NULL or is a 
 *	valid dnstap environment.
 */
#endif /* _DNSTAP_H */
