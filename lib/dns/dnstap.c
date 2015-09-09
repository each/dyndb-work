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

/*! \file */

#include <config.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/sockaddr.h>
#include <isc/time.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/dnstap.h>
#include <dns/name.h>
#include <dns/message.h>

#ifdef DNSTAP
#include "dnstap.pb-c.h"
#include <protobuf-c/protobuf-c.h>
#endif /* DNSTAP */

#define DNSTAP_CONTENT_TYPE	"protobuf:dnstap.Dnstap"
#define DNSTAP_INITIAL_BUF_SIZE 256

typedef struct dtmsg {
	void *buf;
	size_t len;
	Dnstap__Dnstap d;
	Dnstap__Message m;
} dtmsg_t;

#define CHECK(x) do { \
	result = (x); \
	if (result != ISC_R_SUCCESS) \
		goto cleanup; \
	} while (0)

isc_result_t
dns_dt_create(isc_mem_t *mctx, const char *sockpath,
	     unsigned int workers, dns_dtenv_t **envp)
{
#ifdef DNSTAP
	isc_result_t result = ISC_R_SUCCESS;
	fstrm_res res;
	struct fstrm_iothr_options *fopt = NULL;
	struct fstrm_unix_writer_options *fuwopt = NULL;
	struct fstrm_writer *fw = NULL;
	struct fstrm_writer_options *fwopt = NULL;
	dns_dtenv_t *env = NULL;

	/* TODO: log "opening dnstap socket %s", sockpath */

	env = isc_mem_get(mctx, sizeof(dns_dtenv_t));
	if (env == NULL)
		CHECK(ISC_R_NOMEMORY);

	memset(env, 0, sizeof(dns_dtenv_t));

	fwopt = fstrm_writer_options_init();
	if (fwopt == NULL)
		CHECK(ISC_R_NOMEMORY);

	res = fstrm_writer_options_add_content_type(fwopt,
					    DNSTAP_CONTENT_TYPE,
					    sizeof(DNSTAP_CONTENT_TYPE) - 1);
	if (res != fstrm_res_success)
		CHECK(ISC_R_FAILURE);

	fuwopt = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(fuwopt, sockpath);

	fw = fstrm_unix_writer_init(fuwopt, fwopt);
	RUNTIME_CHECK(fw != NULL);

	fopt = fstrm_iothr_options_init();
	fstrm_iothr_options_set_num_input_queues(fopt, workers);
	env->iothr = fstrm_iothr_init(fopt, &fw);
	if (env->iothr == NULL) {
		/* TODO: log "fstrm_iothr_init failed" */
		fstrm_writer_destroy(&fw);
		CHECK(ISC_R_FAILURE);
	}

	isc_mem_attach(mctx, &env->mctx);

	*envp = env;

 cleanup:
	if (fopt != NULL)
		fstrm_iothr_options_destroy(&fopt);

	if (fuwopt != NULL)
		fstrm_unix_writer_options_destroy(&fuwopt);

	if (fwopt != NULL)
		fstrm_writer_options_destroy(&fwopt);

	if (result != ISC_R_SUCCESS) {
		if (env->mctx != NULL)
			isc_mem_detach(&env->mctx);

		if (env != NULL) 
			isc_mem_put(mctx, env, sizeof(dns_dtenv_t));
	}

	return (result);
#else
	UNUSED(sockpath);
	UNUSED(workers);
	UNUSED(envp);

	return (ISC_R_NOTIMPLEMENTED);
#endif /* DNSTAP */
}

static isc_result_t
toregion(dns_dtenv_t *env, isc_region_t *r, const char *str) {
	unsigned char *p = NULL;

	REQUIRE(r != NULL);

	if (str != NULL) {
		p = (unsigned char *) isc_mem_strdup(env->mctx, str);
		if (p == NULL)
			return (ISC_R_NOMEMORY);
	}

	if (r->base != NULL) {
		isc_mem_free(env->mctx, r->base);
		r->length = 0;
	}

	if (p != NULL) {
		r->base = p;
		r->length = strlen((char *) p);
	}

	return (ISC_R_SUCCESS);
}

isc_result_t
dns_dt_setidentity(dns_dtenv_t *env, const char *identity) {
	return (toregion(env, &env->identity, identity));
}

isc_result_t
dns_dt_setversion(dns_dtenv_t *env, const char *version) {
	return (toregion(env, &env->version, version));
}

isc_result_t
dns_dt_init(dns_dtenv_t *env) {
#ifdef DNSTAP
	env->ioq = fstrm_iothr_get_input_queue(env->iothr);
	if (env->ioq == NULL)
		return (ISC_R_FAILURE);
	return (ISC_R_SUCCESS);
#else
	UNUSED(env);

	return (ISC_R_NOTIMPLEMENTED);
#endif /* DNSTAP */
}

void
dns_dt_delete(dns_dtenv_t *env) {
#ifdef DNSTAP
	if (env == NULL)
		return;
	/* TODO: log "closing dnstap socket" */

	fstrm_iothr_destroy(&env->iothr);

	if (env->identity.base != NULL) {
		isc_mem_free(env->mctx, env->identity.base);
		env->identity.length = 0;
	}
	if (env->version.base != NULL) {
		isc_mem_free(env->mctx, env->version.base);
		env->version.length = 0;
	}

	isc_mem_putanddetach(&env->mctx, env, sizeof(*env));
#else
	UNUSED(env);
#endif /* DNSTAP */
}

static isc_result_t
pack_dt(const Dnstap__Dnstap *d, void **buf, size_t *sz) {
	ProtobufCBufferSimple sbuf;

	REQUIRE(d != NULL);
	REQUIRE(sz != NULL);

	memset(&sbuf, 0, sizeof(sbuf));
	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;

	/* Need to use malloc() here because protobuf uses free() */
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL)
		return (ISC_R_NOMEMORY);
	sbuf.must_free_data = 1;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return (ISC_R_FAILURE);
	*buf = sbuf.data;

	return (ISC_R_SUCCESS);
}

static void
send_dt(dns_dtenv_t *env, void *buf, size_t len) {
	fstrm_res res;

	REQUIRE(env != NULL);

	if (buf == NULL)
		return;

	res = fstrm_iothr_submit(env->iothr, env->ioq, buf, len,
				 fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success)
		free(buf);
}

static void
init_msg(dns_dtenv_t *env, dtmsg_t *dm, Dnstap__Message__Type mtype) {
	memset(dm, 0, sizeof(*dm));
	dm->d.base.descriptor = &dnstap__dnstap__descriptor;
	dm->m.base.descriptor = &dnstap__message__descriptor;
	dm->d.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dm->d.message = &dm->m;
	dm->m.type = mtype;

	if (env->identity.length != 0) {
		dm->d.identity.data = env->identity.base;
		dm->d.identity.len = env->identity.length;
		dm->d.has_identity = ISC_TRUE;
	}

	if (env->version.length != 0) {
		dm->d.version.data = env->version.base;
		dm->d.version.len = env->version.length;
		dm->d.has_version = ISC_TRUE;
	}
}

static Dnstap__Message__Type
dnstap_type(dns_dtmsgtype_t msgtype) {
	switch (msgtype) {
	case DNS_DTTYPE_SQ:
		return (DNSTAP__MESSAGE__TYPE__STUB_QUERY);
	case DNS_DTTYPE_SR:
		return (DNSTAP__MESSAGE__TYPE__STUB_RESPONSE);
	case DNS_DTTYPE_CQ:
		return (DNSTAP__MESSAGE__TYPE__CLIENT_QUERY);
	case DNS_DTTYPE_CR:
		return (DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE);
	case DNS_DTTYPE_AQ:
		return (DNSTAP__MESSAGE__TYPE__AUTH_QUERY);
	case DNS_DTTYPE_AR:
		return (DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE);
	case DNS_DTTYPE_RQ:
		return (DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY);
	case DNS_DTTYPE_RR:
		return (DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE);
	case DNS_DTTYPE_FQ:
		return (DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY);
	case DNS_DTTYPE_FR:
		return (DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE);
	default:
		INSIST(0);
	}
}

static void
cpbuf(isc_buffer_t *buf, ProtobufCBinaryData *p, protobuf_c_boolean *has) {
	p->data = isc_buffer_base(buf);
	p->len = isc_buffer_usedlength(buf);
	*has = 1;
}

static void
setaddr(dtmsg_t *dm, isc_sockaddr_t *sa, isc_boolean_t tcp,
	ProtobufCBinaryData *addr, protobuf_c_boolean *has_addr,
	isc_uint32_t *port, protobuf_c_boolean *has_port)
{
	int family = isc_sockaddr_pf(sa);

	if (family != AF_INET6 && family != AF_INET) {
		/* TODO: log error */
		return;
	}

	if (family == AF_INET6) {
		dm->m.socket_family = DNSTAP__SOCKET_FAMILY__INET6;
		addr->data = sa->type.sin6.sin6_addr.s6_addr;
		addr->len = 16;
		*port = ntohs(sa->type.sin6.sin6_port);
	} else {
		dm->m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
		addr->data = (uint8_t *) &sa->type.sin.sin_addr.s_addr;
		addr->len = 4;
		*port = ntohs(sa->type.sin.sin_port);
	}

	if (tcp)
		dm->m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__TCP;
	else
		dm->m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__UDP;

	dm->m.has_socket_protocol = 1;
	dm->m.has_socket_family = 1;
	*has_addr = 1;
	*has_port = 1;
}

void
dns_dt_send(dns_dtenv_t *env, dns_dtmsgtype_t msgtype,
	    isc_sockaddr_t *sa, isc_boolean_t tcp,
	    dns_name_t *zone, dns_message_t *message,
	    isc_time_t *qtime, isc_time_t *rtime,
	    isc_buffer_t *buf)
{
#ifdef DNSTAP
	isc_time_t now, *t;
	dtmsg_t dm;

	UNUSED(msgtype);
	UNUSED(zone);
	UNUSED(message);
	UNUSED(qtime);
	UNUSED(rtime);
	UNUSED(buf);

	TIME_NOW(&now);
	t = &now;

	init_msg(env, &dm, dnstap_type(msgtype));

	if ((msgtype & DNS_DTTYPE_QUERY) != 0) {
		if (qtime != NULL)
			t = qtime;

		dm.m.query_time_sec = isc_time_seconds(t);
		dm.m.has_query_time_sec = 1;
		dm.m.query_time_nsec = isc_time_nanoseconds(t);
		dm.m.has_query_time_nsec = 1;

		cpbuf(buf, &dm.m.query_message, &dm.m.has_query_message);
	} else if ((msgtype & DNS_DTTYPE_RESPONSE) != 0) {
		if (rtime != NULL)
			t = rtime;

		dm.m.response_time_sec = isc_time_seconds(t);
		dm.m.has_response_time_sec = 1;
		dm.m.response_time_nsec = isc_time_nanoseconds(t);
		dm.m.has_response_time_nsec = 1;

		cpbuf(buf, &dm.m.response_message, &dm.m.has_response_message);
	} else {
		/* TODO log error */
		return;
	}

	switch (msgtype) {
	case DNS_DTTYPE_AQ:
	case DNS_DTTYPE_AR:
	case DNS_DTTYPE_CQ:
	case DNS_DTTYPE_CR:
		setaddr(&dm, sa, tcp,
			&dm.m.query_address, &dm.m.has_query_address,
			&dm.m.query_port, &dm.m.has_query_port);
		break;
	case DNS_DTTYPE_RQ:
	case DNS_DTTYPE_RR:
	case DNS_DTTYPE_FQ:
	case DNS_DTTYPE_FR:
		setaddr(&dm, sa, tcp,
			&dm.m.response_address, &dm.m.has_response_address,
			&dm.m.response_port, &dm.m.has_response_port);
		break;
	default:
		/* TODO: log error */
		break;
	}

	if (pack_dt(&dm.d, &dm.buf, &dm.len) == ISC_R_SUCCESS)
		send_dt(env, dm.buf, dm.len);

	return;
#else
	UNUSED(env);
	UNUSED(msgtype);
	UNUSED(sa);
	UNUSED(zone);
	UNUSED(message);
	UNUSED(qtime);
	UNUSED(rtime);
	UNUSED(buf);
#endif /* DNSTAP */
}
