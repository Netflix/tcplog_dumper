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

#ifndef __tcplog_dumper_h__
#define	__tcplog_dumper_h__ 

/* Buffer size allocated for input and output buffers. */
#define	IO_BUF_SIZE	(2*1024*1024)

/* Number of threads to start to process records. */
#define	NUM_THREADS	8

typedef struct ip aligned_ip_hdr __aligned(2);
typedef struct ip6_hdr aligned_ip6_hdr __aligned(2);

struct extract_context;

typedef int tcplog_writev_t(struct extract_context *ctx, struct iovec *iov,
    int iovcnt, int bytelen);
typedef void tcplog_ctx_fini_t(struct extract_context *ctx);

struct extract_context {
	tcplog_writev_t		*tcplog_writev;	/* The writev-ish function */
	tcplog_ctx_fini_t	*ctx_fini;	/* Extra finalization steps */
	void			*ctx_private;	/* Private write-related data */
	void			*ctx_outbuf;	/* Output buffer space */
	struct timeval		*tv_offset;	/* uptime -> UTC offset */
	int			out_fd;		/* The output file descriptor */
	union {
		aligned_ip_hdr	in_iphdr;	/* Incoming IPv4 header */
		aligned_ip6_hdr	in_ip6hdr;	/* Incoming IPv6 header */
	};
	union {
		aligned_ip_hdr	out_iphdr;	/* Outgoing IPv4 header */
		aligned_ip6_hdr	out_ip6hdr;	/* Outgoing IPv6 header */
	};
	uint8_t			af;		/* Address family */
};

void tcplog_xz_init(struct extract_context *ctx);
int writev_int(struct extract_context *ctx, struct iovec *iov, int iovcnt,
    int bytelen);
void do_exit(int rv) __attribute__ ((noreturn));
void do_err(int priority, const char *message, ...) __attribute__ ((noreturn)) __printflike(2, 3);

void idcache_add(const char *id __attribute__((nonnull)), int next_filenum);
void idcache_expire(void);
int *idcache_get(const char *id __attribute__((nonnull)));
void idcache_init(int idx);

#endif /* !__tcplog_dumper_h__ */
