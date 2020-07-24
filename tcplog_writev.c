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

#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>

#include "tcplog_dumper.h"

int
writev_int(struct extract_context *ctx, struct iovec *iov, int iovcnt, int bytelen)
{
	int bytes_left, write_rv;

	bytes_left = bytelen;
	while ((write_rv = writev(ctx->out_fd, iov, iovcnt)) != bytes_left) {
		if (write_rv < 0) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				continue;
			default:
				warn("Error writing to file");
				return (-1);
			}
		}

		/* Update the number of bytes left. */
		assert(bytes_left > write_rv);
		bytes_left -= write_rv;

		/* Delete IOV members that have been completely consumed. */
		while (iov[0].iov_len <= (size_t) write_rv) {
			write_rv -= iov[0].iov_len;
			iov++;
			iovcnt--;
		};
		assert(iovcnt > 0);

		/* Update the partially-consumed IOV member. */
		if (write_rv > 0) {
			iov[0].iov_len -= write_rv;
			iov[0].iov_base = ((uint8_t *)iov[0].iov_base) + write_rv;
		}
	}

	return(0);
}
