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

#include <atf-c.h>

#include <unistd.h>

#include <isc/file.h>
#include <isc/print.h>
#include <isc/types.h>

#include <dns/dnstap.h>
#include <dns/view.h>

#include "dnstest.h"

#ifdef DNSTAP
#include <dns/dnstap.pb-c.h>
#include <protobuf-c/protobuf-c.h>

#define TAPFILE "testdata/dnstap/dnstap.file"
#define TAPSOCK "testdata/dnstap/dnstap.sock"

/*
 * Helper functions
 */
static void
cleanup() {
	(void) isc_file_remove(TAPFILE);
	(void) isc_file_remove(TAPSOCK);
}

/*
 * Individual unit tests
 */

ATF_TC(create);
ATF_TC_HEAD(create, tc) {
	atf_tc_set_md_var(tc, "descr", "set up dnstap environment");
}
ATF_TC_BODY(create, tc) {
	isc_result_t result;
	dns_dtenv_t *dtenv = NULL;

	UNUSED(tc);

	cleanup();

	result = dns_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE(result == ISC_R_SUCCESS);

	result = dns_dt_create(mctx, dns_dtmode_file, TAPFILE, 1, &dtenv);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	if (dtenv != NULL)
		dns_dt_detach(&dtenv);

	ATF_CHECK(isc_file_exists(TAPFILE));

	result = dns_dt_create(mctx, dns_dtmode_usocket, TAPSOCK, 1, &dtenv);
	ATF_CHECK_EQ(result, ISC_R_SUCCESS);
	if (dtenv != NULL)
		dns_dt_detach(&dtenv);

	/* 'create' should succeed, but the file shouldn't exist yet */
	ATF_CHECK(!isc_file_exists(TAPSOCK));

	result = dns_dt_create(mctx, 33, TAPSOCK, 1, &dtenv);
	ATF_CHECK_EQ(result, ISC_R_FAILURE);
	ATF_CHECK_EQ(dtenv, NULL);

	cleanup();

	dns_dt_shutdown();
	dns_test_end();
}

ATF_TC(send);
ATF_TC_HEAD(send, tc) {
	atf_tc_set_md_var(tc, "descr", "send dnstap messages");
}
ATF_TC_BODY(send, tc) {
	isc_result_t result;
	dns_dtenv_t *dtenv = NULL;
	unsigned char zone[DNS_NAME_MAXWIRE];
	unsigned char qambuffer[4096], rambuffer[4096];
	unsigned char qrmbuffer[4096], rrmbuffer[4096];
	isc_buffer_t zb, qamsg, ramsg, qrmsg, rrmsg;
	size_t qasize, qrsize, rasize, rrsize;
	dns_fixedname_t zfname;
	dns_name_t *zname;
	dns_dtmsgtype_t dt;
	dns_view_t *view = NULL;
	dns_compress_t cctx;
	isc_region_t zr;
	isc_sockaddr_t addr;
	struct in_addr in;
	isc_stdtime_t now;
	isc_time_t p, f;

	UNUSED(tc);

	cleanup();

	result = dns_test_begin(NULL, ISC_TRUE);
	ATF_REQUIRE(result == ISC_R_SUCCESS);

	result = dns_test_makeview("test", &view);

	result = dns_dt_create(mctx, dns_dtmode_file, TAPFILE, 1, &dtenv);
	ATF_REQUIRE(result == ISC_R_SUCCESS);

	dns_dt_attach(dtenv, &view->dtenv);
	view->dttypes = DNS_DTTYPE_ALL;

	/*
	 * Set up some test data
	 */
	dns_fixedname_init(&zfname);
	zname = dns_fixedname_name(&zfname);
	isc_buffer_constinit(&zb, "example.com.", 12);
	isc_buffer_add(&zb, 12);
	result = dns_name_fromtext(zname, &zb, NULL, 0, NULL);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);

	memset(&zr, 0, sizeof(zr));
	isc_buffer_init(&zb, zone, sizeof(zone));
	result = dns_compress_init(&cctx, -1, mctx);
	dns_compress_setmethods(&cctx, DNS_COMPRESS_NONE);
	result = dns_name_towire(zname, &cctx, &zb);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	dns_compress_invalidate(&cctx);
	isc_buffer_usedregion(&zb, &zr);

	in.s_addr = inet_addr("10.53.0.1");
	isc_sockaddr_fromin(&addr, &in, 2112);

	isc_stdtime_get(&now);
	isc_time_set(&p, now - 3600, 0); /* past */
	isc_time_set(&f, now + 3600, 0); /* future */

	result = dns_test_getdata("testdata/dnstap/query.auth",
				  qambuffer, sizeof(qambuffer), &qasize);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	isc_buffer_init(&qamsg, qambuffer, qasize);
	isc_buffer_add(&qamsg, qasize);

	result = dns_test_getdata("testdata/dnstap/response.auth",
				  rambuffer, sizeof(rambuffer), &rasize);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	isc_buffer_init(&ramsg, rambuffer, rasize);
	isc_buffer_add(&ramsg, rasize);

	result = dns_test_getdata("testdata/dnstap/query.recursive", qrmbuffer,
				  sizeof(qrmbuffer), &qrsize);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	isc_buffer_init(&qrmsg, qrmbuffer, qrsize);
	isc_buffer_add(&qrmsg, qrsize);

	result = dns_test_getdata("testdata/dnstap/response.recursive",
				  rrmbuffer, sizeof(rrmbuffer), &rrsize);
	ATF_REQUIRE_EQ(result, ISC_R_SUCCESS);
	isc_buffer_init(&rrmsg, rrmbuffer, rrsize);
	isc_buffer_add(&rrmsg, rrsize);

	for (dt = DNS_DTTYPE_SQ; dt <= DNS_DTTYPE_TR; dt <<= 1) {
		isc_buffer_t *m;

		switch (dt) {
		case DNS_DTTYPE_AQ:
			m = &qamsg;
			break;
		case DNS_DTTYPE_AR:
			m = &ramsg;
			break;
		default:
			m = &qrmsg;
			if ((dt & DNS_DTTYPE_RESPONSE) != 0)
				m = &ramsg;
			break;
		}

		dns_dt_send(view, dt, &addr, ISC_FALSE, &zr, &p, &f, m);
		dns_dt_send(view, dt, &addr, ISC_FALSE, &zr, NULL, &f, m);
		dns_dt_send(view, dt, &addr, ISC_FALSE, &zr, &p, NULL, m);
		dns_dt_send(view, dt, &addr, ISC_FALSE, &zr, NULL, NULL, m);
		dns_dt_send(view, dt, &addr, ISC_TRUE, &zr, &p, &f, m);
		dns_dt_send(view, dt, &addr, ISC_TRUE, &zr, NULL, &f, m);
		dns_dt_send(view, dt, &addr, ISC_TRUE, &zr, &p, NULL, m);
		dns_dt_send(view, dt, &addr, ISC_TRUE, &zr, NULL, NULL, m);
	}

	dns_dt_detach(&view->dtenv);
	dns_dt_detach(&dtenv);
	dns_dt_shutdown();
	dns_view_detach(&view);

	/*
	 * XXX now read back and check content.
	 */

	// cleanup();

	dns_test_end();
}

#else
ATF_TC(untested);
ATF_TC_HEAD(untested, tc) {
	atf_tc_set_md_var(tc, "descr", "skipping dnstap test");
}
ATF_TC_BODY(untested, tc) {
	UNUSED(tc);
	atf_tc_skip("dnstap not available");
}
#endif

/*
 * Main
 */
ATF_TP_ADD_TCS(tp) {
#ifdef DNSTAP
	ATF_TP_ADD_TC(tp, create);
	ATF_TP_ADD_TC(tp, send);
	//ATF_TP_ADD_TC(tp, totext);
#else
	ATF_TP_ADD_TC(tp, untested);
#endif

	return (atf_no_error());
}
