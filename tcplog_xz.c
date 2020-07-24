/*-
 * Copyright (c) 2016
 *	Netflix Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#ifndef NO_REUSE_LZMA
#include <sys/mman.h>
#endif
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lzma.h>

#include "tcplog_dumper.h"

static void	tcplog_xz_fini(struct extract_context *ctx);
static int	write_xz(struct extract_context *ctx, void *in, size_t in_len,
    bool finished);
static int	write_xz_flush(struct extract_context *ctx);
static int	writev_xz(struct extract_context *ctx, struct iovec *iov,
    int iovcnt, int bytelen __unused);

void
tcplog_xz_init(struct extract_context *ctx)
{
	lzma_stream tmp = LZMA_STREAM_INIT;
	lzma_ret rv;
	lzma_stream *strm;

	/* Assign the output buffers. */
	if ((ctx->ctx_outbuf = malloc(IO_BUF_SIZE)) == NULL)
		do_err(1, "Error allocating %u bytes for output buffer",
		    IO_BUF_SIZE);

	/*
	 * Allocate a stream structure and initialize it in a pendantically-
	 * correct way.
	 */
	if ((strm = malloc(sizeof(*strm))) == NULL)
		do_err(1, "Error allocating %zu bytes for XZ stream",
		    sizeof(*strm));
	*strm = tmp;
	ctx->ctx_private = (void *)strm;

	/*
	 * Initialize the stream for encoding using compression level 0 and
	 * CRC64. For these files, compression level 0 seems to provide
	 * compression that is approximately as good as the default level (6),
	 * while using less CPU.
	 */
	rv = lzma_easy_encoder(strm, 0, LZMA_CHECK_CRC64);
	if (rv != LZMA_OK) {
		fprintf(stderr, "Unable to initialize XZ encoder.\n");
		do_exit(1);
	}
	strm->next_out = ctx->ctx_outbuf;
	strm->avail_out = IO_BUF_SIZE;

	/* Set the function pointers in the context. */
	ctx->tcplog_writev = writev_xz;
	ctx->ctx_fini = tcplog_xz_fini;
}

static int
write_xz_flush(struct extract_context *ctx)
{
	struct iovec iov;
	lzma_stream *strm;
	int rv;

	strm = (lzma_stream *)ctx->ctx_private;

	/* Write out the buffer. */
	iov.iov_base = ctx->ctx_outbuf;
	iov.iov_len = (IO_BUF_SIZE) - strm->avail_out;
	rv = writev_int(ctx, &iov, 1, iov.iov_len);

	/* Refill the buffer. */
	if (!rv) {
		strm->next_out = ctx->ctx_outbuf;
		strm->avail_out = IO_BUF_SIZE;
	}

	return (rv);
}

static int
write_xz(struct extract_context *ctx, void *in, size_t in_len, bool finished)
{
	lzma_ret rv;
	lzma_stream *strm;
	lzma_action action;

	strm = (lzma_stream *)ctx->ctx_private;
	assert(strm->avail_in == 0);

	action = finished ? LZMA_FINISH : LZMA_RUN;
	strm->next_in = in;
	strm->avail_in = in_len;
	while (finished || strm->avail_in) {
		rv = lzma_code(strm, action);
		if (!(rv == LZMA_OK || rv == LZMA_STREAM_END ||
		    rv == LZMA_BUF_ERROR)) {
			fprintf(stderr, "Error encoding XZ stream.\n");
			return (-1);
		}
		if (rv == LZMA_STREAM_END || strm->avail_out == 0)
			if (write_xz_flush(ctx))
				return (-1);
		if (rv == LZMA_STREAM_END) {
			assert(finished);
			assert(strm->avail_in == 0);
			return (0);
		}
	}
	return (0);
}

static int
writev_xz(struct extract_context *ctx, struct iovec *iov, int iovcnt, int bytelen __unused)
{
	int i;

	for (i = 0; i < iovcnt; i++)
		if (write_xz(ctx, iov[i].iov_base, iov[i].iov_len, false))
			return (-1);

	return (0);
}

static void
tcplog_xz_fini(struct extract_context *ctx)
{

	(void)write_xz(ctx, NULL, (size_t)0, true);
	lzma_end((lzma_stream *)ctx->ctx_private);
	free(ctx->ctx_outbuf);
	free(ctx->ctx_private);
}
