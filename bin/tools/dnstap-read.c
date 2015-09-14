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
/*
 * Portions of this code were adapted from dnstap-ldns:
 *
 * Copyright (c) 2014 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/dnstap.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/result.h>

isc_mem_t *mctx = NULL;
isc_boolean_t memrecord = ISC_FALSE;
isc_boolean_t printmessage = ISC_FALSE;
isc_boolean_t yaml = ISC_FALSE;

const char *program = "dnstap-read";

#define CHECKM(op, msg) \
	do { result = (op);					  \
	       if (result != ISC_R_SUCCESS) {			  \
			fprintf(stderr, 			  \
			        "%s: %s: %s\n", program, msg,	  \
				      isc_result_totext(result)); \
			goto cleanup;				  \
		}						  \
	} while (0)

static void
fatal(const char *format, ...) {
	va_list args;

	fprintf(stderr, "%s: fatal: ", program);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(1);
}

static void
usage(void) {
	fprintf(stderr, "dnstap-read [-mp] [filename]\n");
	fprintf(stderr, "\t-m\ttrace memory allocations\n");
	fprintf(stderr, "\t-p\tprint the full DNS message\n");
	fprintf(stderr, "\t-y\tprint YAML format (implies -p)\n");
}

static isc_boolean_t
dnstap_file(struct fstrm_reader *r) {
	fstrm_res res;
	const struct fstrm_control *control = NULL;
	const char *dnstap_type = "protobuf:dnstap.Dnstap";
	const uint8_t *rtype = NULL;
	size_t dlen = strlen(dnstap_type), rlen = 0;
	size_t n = 0;

	res = fstrm_reader_get_control(r, FSTRM_CONTROL_START, &control);
	if (res != fstrm_res_success)
		return (ISC_FALSE);

	res = fstrm_control_get_num_field_content_type(control, &n);
	if (res != fstrm_res_success)
		return (ISC_FALSE);
	if (n > 0) {
		res = fstrm_control_get_field_content_type(control, 0,
							   &rtype, &rlen);
		if (res != fstrm_res_success)
			return (ISC_FALSE);

		if (rlen != dlen)
			return (ISC_FALSE);

		if (memcmp(dnstap_type, rtype, dlen) == 0)
			return (ISC_TRUE);
	}

	return (ISC_FALSE);
}

static void
print_yaml(dns_dtdata_t *d) {
	Dnstap__Dnstap *frame = d->frame;
	Dnstap__Message *m = frame->message;
	const ProtobufCEnumValue *ftype, *mtype;

	ftype = protobuf_c_enum_descriptor_get_value(
				     &dnstap__dnstap__type__descriptor,
				     frame->type);
	if (ftype == NULL)
		return;

	printf("type: %s\n", ftype->name);

	if (frame->has_identity)
		printf("identity: %.*s\n", (int) frame->identity.len,
		       frame->identity.data);

	if (frame->has_version)
		printf("version: %.*s\n", (int) frame->version.len,
		       frame->version.data);

	if (frame->type != DNSTAP__DNSTAP__TYPE__MESSAGE)
		return;

	printf("message:\n");

	mtype = protobuf_c_enum_descriptor_get_value(
				     &dnstap__message__type__descriptor,
				     m->type);
	if (mtype == NULL)
		return;

	printf("  type: %s\n", mtype->name);

	if (!isc_time_isepoch(&d->qtime)) {
		char buf[100];
		isc_time_formattimestamp(&d->qtime, buf, sizeof(buf));
		printf("  query_time: !!timestamp %s\n", buf);
	}

	if (!isc_time_isepoch(&d->rtime)) {
		char buf[100];
		isc_time_formattimestamp(&d->rtime, buf, sizeof(buf));
		printf("  response_time: !!timestamp %s\n", buf);
	}

	if (m->has_socket_family) {
		const ProtobufCEnumValue *type =
			protobuf_c_enum_descriptor_get_value(
				&dnstap__socket_family__descriptor,
				m->socket_family);
		if (type != NULL)
			printf("  socket_family: %s\n", type->name);
	}

	printf("  socket_protocol: %s\n", d->tcp ? "TCP" : "UDP");

	if (m->has_query_address) {
		ProtobufCBinaryData *ip = &m->query_address;
		char buf[100];

		(void)inet_ntop(ip->len == 4 ? AF_INET : AF_INET6,
				ip->data, buf, sizeof(buf));
		printf("  query_address: %s\n", buf);
	}

	if (m->has_response_address) {
		ProtobufCBinaryData *ip = &m->response_address;
		char buf[100];

		(void)inet_ntop(ip->len == 4 ? AF_INET : AF_INET6,
				ip->data, buf, sizeof(buf));
		printf("  response_address: %s\n", buf);
	}

	if (m->has_query_port)
		printf("  query_port: %u\n", m->query_port);

	if (m->has_response_port)
		printf("  response_port: %u\n", m->response_port);

	if (m->has_query_zone) {
		isc_result_t result;
		dns_fixedname_t fn;
		dns_name_t *name;
		isc_buffer_t b;
		dns_decompress_t dctx;

		dns_fixedname_init(&fn);
		name = dns_fixedname_name(&fn);

		isc_buffer_init(&b, m->query_zone.data, m->query_zone.len);
		isc_buffer_add(&b, m->query_zone.len);

		dns_decompress_init(&dctx, -1, DNS_DECOMPRESS_NONE);
		result = dns_name_fromwire(name, &b, &dctx, 0, NULL);
		if (result == ISC_R_SUCCESS) {
			printf("  query_zone: ");
			dns_name_print(name, stdout);
			printf("\n");
		}
	}

	if (d->msg != NULL)
		printf("  %s: |\n", ((d->type & DNS_DTTYPE_QUERY) != 0)
				     ? "query_message" : "response_message");
};

int
main(int argc, char *argv[]) {
	isc_result_t result;
	struct fstrm_file_options *fopt;
	struct fstrm_reader *reader = NULL;
	fstrm_res res;
	dns_message_t *message = NULL;
	isc_buffer_t *b = NULL;
	dns_dtdata_t *dt = NULL;
	int rv = 0, ch;

	while ((ch = isc_commandline_parse(argc, argv, "mpy")) != -1) {
		switch (ch) {
			case 'm':
				isc_mem_debugging |= ISC_MEM_DEBUGRECORD;
				memrecord = ISC_TRUE;
				break;
			case 'p':
				printmessage = ISC_TRUE;
				break;
			case 'y':
				yaml = ISC_TRUE;
				printmessage = ISC_TRUE;
				break;
			default:
				usage();
				exit(1);
		}
	}

	argc -= isc_commandline_index;
	argv += isc_commandline_index;

	if (argc < 1)
		fatal("no file specified");

	fopt = fstrm_file_options_init();
	if (fopt == NULL)
		fatal("fstrm_file_options_init failed");
	fstrm_file_options_set_file_path(fopt, argv[0]);

	reader = fstrm_file_reader_init(fopt, NULL);
	if (reader == NULL)
		fatal("%s: fstrm_file_reader_init failed", argv[0]);
	res = fstrm_reader_open(reader);
	if (res != fstrm_res_success)
		fatal("fstrm_reader_open failed");
	fstrm_file_options_destroy(&fopt);

	if (!dnstap_file(reader))
		fatal("%s is not a dnstap file", argv[0]);

	RUNTIME_CHECK(isc_mem_create(0, 0, &mctx) == ISC_R_SUCCESS);

	for (;;) {
		isc_region_t input;
		const uint8_t *data;
		size_t datalen;

		res = fstrm_reader_read(reader, &data, &datalen);
		if (res != fstrm_res_success) {
			if (res != fstrm_res_stop)
				fatal("fstrm_reader_read() failed");
			break;
		}

		DE_CONST(data, input.base);
		input.length = datalen;

		if (b != NULL)
			isc_buffer_free(&b);
		isc_buffer_allocate(mctx, &b, 2048);
		if (b == NULL)
			fatal("out of memory");

		CHECKM(dns_dt_parse(mctx, &input, &dt), "dns_dt_parse");

		if (yaml)
			print_yaml(dt);
		else {
			CHECKM(dns_dt_datatotext(dt, &b), "dns_dt_datatotext");
			printf("%.*s\n", (int) isc_buffer_usedlength(b),
			       (char *) isc_buffer_base(b));
		}

		if (printmessage && dt->msg != NULL) {
			size_t textlen = 2048;

			isc_buffer_clear(b);

			for (;;) {
				isc_buffer_reserve(&b, textlen);
				if (b == NULL)
					fatal("out of memory");
				result = dns_message_totext(dt->msg,
						    &dns_master_style_debug,
						    0, b);
				if (result == ISC_R_NOSPACE) {
					isc_buffer_free(&b);
					textlen *= 2;
					continue;
				} else if (result == ISC_R_SUCCESS) {
					printf("%.*s\n",
					       (int) isc_buffer_usedlength(b),
					       (char *) isc_buffer_base(b));
					isc_buffer_free(&b);
				} else {
					isc_buffer_free(&b);
					CHECKM(result, "dns_message_totext");
				}
				break;
			}
		}

		if (yaml)
			printf("---\n");

		dns_dtdata_free(&dt);
	}

 cleanup:
	if (dt != NULL)
		dns_dtdata_free(&dt);
	if (reader != NULL)
		fstrm_reader_destroy(&reader);
	if (message != NULL)
		dns_message_destroy(&message);
	if (b != NULL)
		isc_buffer_free(&b);
	isc_mem_destroy(&mctx);

	exit(rv);
}
