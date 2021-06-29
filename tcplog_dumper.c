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
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <dev/tcp_log/tcp_log_dev.h>
#include <machine/atomic.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_log_buf.h>
#include <netinet/tcp_var.h>
#include <pcap/pcap.h>
#include <assert.h>
#include <bitstring.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "tcplog_dumper.h"

static __inline u_int min(u_int a, u_int b) { return (a < b ? a : b); }

/* PCAP-NG defines */
#define	MAGIC_NG	0x1A2B3C4D
#define	MAJOR_NG	1
#define	MINOR_NG	0

#define	BT_IDB		0x00000001
#define	BT_EPB		0x00000006
#define	BT_SHB		0x0A0D0D0A
#define	BT_CB_COPY	0x00000BAD
#define	BT_CB_NOCOPY	0x40000BAD

#define	OPT_ENDOFOPT		0
#define	OPT_COMMENT		1
#define	OPT_EPB_FLAGS_WORD	2
#define	OPT_CUST_BIN_COPY	2989
#define	OPT_CUST_BIN_NOCOPY	2989

#define	MAX_SNAPLEN	(sizeof(uint32_t) + sizeof(struct ip6_hdr) + TCP_MAXHLEN)
#define	MAX_IOVS	64

enum compression_types {
	COMPRESSION_NONE,
	COMPRESSION_XZ,
};
static enum compression_types compression = COMPRESSION_NONE;

static const char default_directory[] = "/var/log/tcplog_dumps";
static const char default_filename[] = "/dev/tcp_log";
static const char default_username[] = "nobody";

static bool do_syslog = false;
static volatile bool quit_requested = false;
static bool reset_log_file = false;
static int exit_code = 0;
static volatile int queued_records = 0;
#define	QUEUED_RECORDS_HIWAT	1000
#define	QUEUED_RECORDS_LOWAT	900

struct log_queue {
	STAILQ_ENTRY(log_queue)	lq_link;
	void			*lq_log;
	int			lq_dirfd;
};
STAILQ_HEAD(loghead, log_queue);
static struct loghead bbr_loghead[NUM_THREADS];
static pthread_mutex_t bbr_queue_mtx[NUM_THREADS];
static pthread_cond_t bbr_queue_cond[NUM_THREADS];
static pthread_t bbr_tid[NUM_THREADS];
static int bbr_threads = 0;
static pthread_t main_thread_tid;
static pthread_mutex_t log_record_mutex;
static pthread_mutex_t queuewait_mutex;
static pthread_cond_t queuewait_cond;


static void
log_message(int priority, const char *message, ...) __printflike(2, 3);

static void
process_sighup(int signo __unused)
{

	reset_log_file = true;
}

static void
process_sigterm(int signo __unused)
{

	quit_requested = true;
}

/* A no-op; this just serves to break us from a blocked read. */
static void
process_sigusr2(int signo __unused)
{

	return;
}

static void
log_message(int priority, const char *message, ...)
{
	va_list ap;

	va_start(ap, message);
	if (do_syslog)
		vsyslog(priority, message, ap);
	else {
		vfprintf(stderr, message, ap);
		fprintf(stderr, "\n");
	}
	va_end(ap);
}

/*
 * Wake up any threads that are waiting on a condition.
 */
static void
signal_all_threads(void)
{
	int i;

	for (i = 0; i < bbr_threads; i++) {
		pthread_mutex_lock(&bbr_queue_mtx[i]);
		pthread_cond_signal(&bbr_queue_cond[i]);
		pthread_mutex_unlock(&bbr_queue_mtx[i]);
	}

	/* Wake up the main thread. */
	if (queued_records >= QUEUED_RECORDS_LOWAT) {
		pthread_mutex_lock(&queuewait_mutex);
		pthread_cond_signal(&queuewait_cond);
		pthread_mutex_unlock(&queuewait_mutex);
	}
	if (pthread_self() != main_thread_tid)
		pthread_kill(main_thread_tid, SIGUSR2);
}

void
do_exit(int rv)
{

	exit_code = rv;
	quit_requested = 1;
	signal_all_threads();
	exit(rv);
}

void
do_err(int rv, const char *message, ...)
{
	va_list ap;

	exit_code = rv;
	quit_requested = 1;
	signal_all_threads();

	va_start(ap, message);
	verr(rv, message, ap);
	va_end(ap);
}


/*
 * Create an IP checksum from a header.
 */
static void
add_ip_cksum(struct ip *hdr)
{
	uint16_t *in;
	uint32_t sum;

	/* Assert on alignment. */
	assert(((uintptr_t)hdr) % 2 == 0);

	/*
	 * We optimize this in two ways:
	 * 1. Assume we will never have options.
	 * 2. Ignore the checksum field (index 5). 
	 *
	 * For purposes of this file, these should be safe assumptions.
	 */
	in = (uint16_t *)hdr;
	sum = in[0] + in[1] + in[2] + in[3] + in[4] + in[6] + in[7] +
	    in[8] + in[9];

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = (~sum & 0xffff);

	hdr->ip_sum = sum;
}

/*
 * Create a TCP checksum from a header.
 */
static void
add_tcp_cksum(const struct extract_context *ctx, struct tcphdr *th,
    uint16_t len)
{
	register const uint16_t *in;
	register uint32_t sum;
	int tcp_hlen;

	/* Assert on alignment. */
	assert(((uintptr_t)th) % 2 == 0);

	if (ctx->af == AF_INET) {
		/* Add the pseudo_hdr. */
		in = (const uint16_t *)(&ctx->in_iphdr);
		sum = in[6] + in[7] + in[8] + in[9];
		sum += htons(IPPROTO_TCP);
		sum += htons(len);
	} else {
		/* Add the pseudo_hdr. */
		in = (const uint16_t *)(&ctx->in_ip6hdr);
		sum = in[4] + in[5] + in[6] + in[7] + in[8] + in[9] + in[10] +
		    in[11] + in[12] + in[13] + in[14] + in[15] + in[16] +
		    in[17] + in[18] + in[19];
		sum += htons(len);
		sum += htons(IPPROTO_TCP);
	}

	/* Add the fixed TCP header (less the checksum). */
	in = (const uint16_t *)th;
	sum += in[0] + in[1] + in[2] + in[3] + in[4] + in[5] + in[6] +
	    in[7] + in[9];

	/* Add the TCP options. */
	tcp_hlen = th->th_off << 2;
	tcp_hlen -= sizeof(struct tcphdr);
	in = (const uint16_t *)(th + 1);
	while (tcp_hlen) {
		sum += in[0] + in[1];
		in += 2;
		tcp_hlen -= 4;
	}

	/*
	 * Because we always fill the data portion with 0s, we don't need
	 * to include it in the checksum calculation. Yay!
	 */

	/* Calculate and store the final checksum. */
	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = (~sum & 0xffff);

	th->th_sum = sum;
}

struct pcapng_sh {
	uint32_t	type;
	uint32_t	hdrlen1;
	uint32_t	magic;
	uint16_t	major;
	uint16_t	minor;
	int64_t		seclen;
	/* Options go here */
} __packed;

struct pcapng_idb {
	uint32_t	type;
	uint32_t	len1;
	uint16_t	linktype;
	uint16_t	reserved;
	uint32_t	snaplen;
	/* Options go here */
} __packed;

struct pcapng_epb {
	uint32_t	type;
	uint32_t	len1;
	uint32_t	intid;
	uint32_t	ts_high;
	uint32_t	ts_low;
	uint32_t	caplen;
	uint32_t	pktlen;
	/*
	 * Start of packet data. Because we use a NULL header, we just
	 * include it here.
	 */
	uint32_t	protocol;
	uint8_t		pktdata[0];
} __packed;

struct pcapng_epb_flags_opt {
	uint16_t	code;
	uint16_t	len;
	uint32_t	flags_word;
} __packed;

struct pcapng_nflx_block {
	uint32_t	type;
	uint32_t	len1;
	uint32_t	pen;
	uint32_t	nflx_type;
} __packed;

enum netflix_block_types {
	NFLX_EVENT_BLOCK=1,
	NFLX_SKIPPED_BLOCK,
};

struct pcapng_nflx_eventblock {
	struct pcapng_nflx_block	hdr;
};

struct pcapng_nflx_skipped {
	struct pcapng_nflx_block	hdr;
	uint32_t			num_skipped;
};

struct pcapng_blockend {
	uint32_t	lastopt;
	uint32_t	blocklen;
} __packed;

struct pcapng_nflx_opt {
	uint16_t	code;
	uint16_t	len;
	uint32_t	pen;
	uint32_t	nflx_type;
	uint8_t		optdata[0];
} __packed;

enum netflix_opt_types {
	NFLX_OPT_VERSION=1,
	NFLX_OPT_TCPINFO,
	NFLX_OPT_TCPVERBOSE,
	NFLX_OPT_DUMPINFO,
	NFLX_OPT_DUMPTIME,
	NFLX_OPT_STACKNAME,
};

/* https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers */
#define	NFLX_PEN	10949

struct stacknames {
	const char *s_stackname;
	int s_strlen;
};
static struct stacknames stacknames[256];
static void *stacknamebuf = NULL;
static pthread_rwlock_t stacknames_lock;

/*
 * Refesh the stack name-to-ID mappings.
 *
 * This will clear all the old mappings and create new ones. It must be
 * called while holding a write lock on stacknames_lock.
 * Further, because this function will free the storage used for stack names,
 * any caller that desires to use the stack name must hold at least a read
 * lock on stacknames_lock as long as it needs the stack name pointer to
 * be valid.
 */
static void refresh_stack_names(void) __requires_exclusive(stacknames_lock);
static void
refresh_stack_names(void)
{
	struct tcp_function_info *tfi;
	caddr_t tfi_end;
	size_t len;
	int rv;

	/* Get the new mappings. */
	len = 0;
	rv = sysctlbyname("net.inet.tcp.function_info", NULL, &len, NULL, 0);
	if (rv < 0 && errno != ENOMEM) {
		log_message(LOG_ERR, "Unable to retrieve length of function "
		    "ID mappings (%d: %s)", rv, strerror(errno));
		return;
	}
	if (len == 0)
		return;
	tfi = malloc(len);
	if (tfi == NULL) {
		log_message(LOG_ERR, "Unable to allocate buffer for function "
		    "ID mappings");
		return;
	}
	rv = sysctlbyname("net.inet.tcp.function_info", tfi, &len, NULL, 0);
	if (rv < 0) {
		log_message(LOG_ERR, "Unable to retrieve function ID "
		    "mappings (%d: %s)", rv, strerror(errno));
		free(tfi);
		return;
	}

	/*
	 * Now that we have the mappings, clear the old mappings and install
	 * the new ones.
	 */
	memset(stacknames, 0, sizeof(stacknames));
	if (stacknamebuf != NULL)
		free(stacknamebuf);
	stacknamebuf = tfi;
	tfi_end = (caddr_t)tfi + len;
	for (; (caddr_t)tfi < tfi_end; tfi++) {
		/* Skip aliases. */
		if (strncmp(tfi->tfi_name, tfi->tfi_alias,
		    TCP_FUNCTION_NAME_LEN_MAX))
			continue;
		stacknames[tfi->tfi_id].s_stackname = tfi->tfi_name;
		stacknames[tfi->tfi_id].s_strlen = strlen(tfi->tfi_name);
	}
}

static void
init_stack_names(void)
{

	pthread_rwlock_init(&stacknames_lock, NULL);
	pthread_rwlock_wrlock(&stacknames_lock);
	memset(stacknames, 0, sizeof(stacknames));
	refresh_stack_names();
	pthread_rwlock_unlock(&stacknames_lock);
}

static void
free_iov_allocs(struct iovec *iov, int iovcnt, bitstr_t *free_map)
{
	int i;

	for (bit_ffs(free_map, iovcnt, &i); i >= 0;
	    bit_ffs_at(free_map, i + 1, iovcnt, &i))
		free(iov[i].iov_base);
}

static char junk[MAX_SNAPLEN];

#ifndef CTASSERT
#define	CTASSERT(x)	_Static_assert(x, "Compile-time assertion failed")
#endif

/*
 * pcap_epb_flags_opt() adds a EPB flags word option indicating the packet direction.
 * This option is only included in the enhanced packet block.
 */
static int
pcap_epb_flags_opt(bool inbound, struct iovec *iov, int *iovcnt, bitstr_t *free_map)
{
	struct pcapng_epb_flags_opt *epb_flags_opt;

	epb_flags_opt = malloc(sizeof(struct pcapng_epb_flags_opt));
	if (epb_flags_opt == NULL) {
		warn("Error allocating space for the EPB flags word");
		return (0);
	}
	epb_flags_opt->code = OPT_EPB_FLAGS_WORD;
	epb_flags_opt->len = sizeof(uint32_t);
	if (inbound) {
		/* Inbound packet. */
		epb_flags_opt->flags_word = 0x00000001;
	} else {
		/* Outbound packet. */
		epb_flags_opt->flags_word = 0x00000002;
	}
	iov[*iovcnt].iov_base = epb_flags_opt;
	iov[*iovcnt].iov_len = sizeof(struct pcapng_epb_flags_opt);
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;
	return (sizeof(struct pcapng_epb_flags_opt));
}

/*
 * pcap_nflx_opt_alloc() allocates memory for a Netflix custom option.
 * These options can be used in custom or standard blocks.
 */
static void *
pcap_nflx_opt_alloc(uint32_t type, uint32_t len, bool in_cb)
{
	struct pcapng_nflx_opt *opt;

	assert(len + 8 <= UINT16_MAX);
	opt = malloc(sizeof(struct pcapng_nflx_opt));
	if (opt == NULL) {
		warn("Error allocating space for an option buffer");
		return (NULL);
	}

	/*
	 * When using this custom option in a custom block, store the code, len, and
	 * pen in little endian.
	 * In all other cases, store these fields in host byte order.
	 * The custom option value, including the NFLX type, is always stored in
	 * little endian.
	 */
	if (in_cb) {
		opt->code = htole16(OPT_CUST_BIN_COPY);
		opt->len = htole16(len + 8);
		opt->pen = htole32(NFLX_PEN);
	} else {
		opt->code = OPT_CUST_BIN_COPY;
		opt->len = len + 8;
		opt->pen = NFLX_PEN;
	}
	opt->nflx_type = htole32(type);
	return (opt);
}

/*
 * We assume that we will end up with data aligned on a 4-byte boundary when
 * we copy out the tcp log buffer up to (but not including) the tlb_th member.
 */
CTASSERT(offsetof(struct tcp_log_buffer, tlb_th) % 4 == 0);

/*
 * We also assume that time_t is a 64-bit entity, so basically this excludes i386.
 */
CTASSERT(sizeof(time_t) == 8);

/*
 * pcap_dumptime_opt() adds a custom option containing the time (in seconds since the
 * Unix epoch) when the file was written.
 * This custom option is only included in the section header block.
 */
static int
pcap_dumptime_opt(time_t *dumptime, struct iovec *iov, int *iovcnt,
    bitstr_t *free_map)
{
	void *opt;
	time_t *time;
	int rv;

	/*
	 * Allocate the netflix option header and body. If either fails,
	 * give up and return an error.
	 */
	opt = pcap_nflx_opt_alloc(NFLX_OPT_DUMPTIME, sizeof(time_t), false);
	if (opt == NULL)
		return (0);

	time = malloc(sizeof(time_t));
	if (time == NULL) {
		warn("Error allocating space for the dumptime");
		free(opt);
		return (0);
	}
	*time = htole64(*dumptime);
	/*
	 * Add the option header and body to the IOV. Because we allocated
	 * space for these, we also need to mark these in the free_map.
	 */
	iov[*iovcnt].iov_base = opt;
	iov[*iovcnt].iov_len = sizeof(struct pcapng_nflx_opt);
	rv = iov[*iovcnt].iov_len;
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;
	iov[*iovcnt].iov_base = time;
	iov[*iovcnt].iov_len = sizeof(time_t);
	rv += iov[*iovcnt].iov_len;
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;

	return (rv);
}

/*
 * pcap_version_opt() adds a custom option contaning the version of the file format.
 * This custom option is only included in the section header block.
 */
static int
pcap_version_opt(struct iovec *iov, int *iovcnt, bitstr_t *free_map)
{
	void *opt;
	uint32_t *version;
	int rv;

	/*
	 * Allocate the netflix option header and body. If either fails,
	 * give up and return an error.
	 */
	opt = pcap_nflx_opt_alloc(NFLX_OPT_VERSION, sizeof(uint32_t), false);
	if (opt == NULL)
		return (0);

	version = malloc(sizeof(uint32_t));
	if (version == NULL) {
		warn("Error allocating space for the version identifier");
		free(opt);
		return (0);
	}

	/*
	 * We checked the log format version at startup. So, we can
	 * statically compile that here.
	 */
	*version = htole32(TCP_LOG_BUF_VER);

	/*
	 * Add the option header and body to the IOV. Because we allocated
	 * space for these, we also need to mark these in the free_map.
	 */
	iov[*iovcnt].iov_base = opt;
	iov[*iovcnt].iov_len = sizeof(struct pcapng_nflx_opt);
	rv = iov[*iovcnt].iov_len;
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;
	iov[*iovcnt].iov_base = version;
	iov[*iovcnt].iov_len = sizeof(uint32_t);
	rv += iov[*iovcnt].iov_len;
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;

	return (rv);
}

/*
 * We  assume that struct timeval consists of two 64-bit entities, so basically assumes
 * a 64-bit platform.
 */
CTASSERT(sizeof(struct timeval) == 16);

/*
 * pcap_dumpinfo_opt() adds a custom option contaning the stack ID and stack name.
 * This custom option is only included in the section header block.
 */
static int
pcap_dumpinfo_opt(struct tcp_log_header *hdr, struct iovec *iov, int *iovcnt,
    bitstr_t *free_map)
{
	void *opt;
	struct tcp_log_header *hdr_le;
	int rv;

	opt = pcap_nflx_opt_alloc(NFLX_OPT_DUMPINFO,
	    sizeof(struct tcp_log_header), false);
	if (opt == NULL)
		return (0);

#if BYTE_ORDER == LITTLE_ENDIAN
	hdr_le = hdr;
#else
	hdr_le = malloc(sizeof(struct tcp_log_header));
	if (hdr_le == NULL) {
		warn("Error allocating space for the tcp_log_header");
		free(opt);
		return (0);
	}
	/*
	 * Convert all fields, except the endpoint information, to litte endian.
	 * Keep the endpoint information in network byte order, aka big endian.
	 */
	hdr_le->tlh_version = htole32(hdr->tlh_version);
	hdr_le->tlh_type = htole32(hdr->tlh_type);
	hdr_le->tlh_length = htole64(hdr->tlh_length);
	hdr_le->tlh_ie = hdr->tlh_ie;
	hdr_le->tlh_offset.tv_sec = htole64(hdr->tlh_offset.tv_sec);
	hdr_le->tlh_offset.tv_usec = htole64(hdr->tlh_offset.tv_usec);
	memcpy(hdr_le->tlh_id, hdr->tlh_id ,TCP_LOG_ID_LEN);
	memcpy(hdr_le->tlh_reason, hdr->tlh_reason, TCP_LOG_REASON_LEN);
	memcpy(hdr_le->tlh_tag, hdr->tlh_tag, TCP_LOG_TAG_LEN);
	hdr_le->tlh_af = hdr->tlh_af;
	memcpy(hdr_le->_pad, hdr->_pad, 7);
#endif

	/* Update the IOV. */
	iov[*iovcnt].iov_base = opt;
	iov[*iovcnt].iov_len = sizeof(struct pcapng_nflx_opt);
	rv = iov[*iovcnt].iov_len;
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;
	iov[*iovcnt].iov_base = hdr_le;
	iov[*iovcnt].iov_len = sizeof(struct tcp_log_header);
	rv += iov[*iovcnt].iov_len;
#if BYTE_ORDER == BIG_ENDIAN
	bit_set(free_map, *iovcnt);
#endif
	(*iovcnt)++;

	return (rv);
}

/*
 * pcap_stackname_opt() adds a custom option containing the stack ID and stack name.
 * This custom option is only included in the section header block.
 */
static int pcap_stackname_opt(uint8_t *stackid, struct iovec *iov, int *iovcnt,
    bitstr_t *free_map) __locks_shared(stacknames_lock);
static int
pcap_stackname_opt(uint8_t *stackid, struct iovec *iov, int *iovcnt,
    bitstr_t *free_map)
{
	const char *stackname;
	void *opt;
	int stacknamelen, rv;

	/* Try to find the stack. */
	pthread_rwlock_rdlock(&stacknames_lock);
	stackname = stacknames[*stackid].s_stackname;
	stacknamelen = stacknames[*stackid].s_strlen;

	/*
	 * If we didn't acquire the stack name, try to refresh our view of
	 * the stack names.
	 */
	if (stackname == NULL) {
		pthread_rwlock_unlock(&stacknames_lock);
		pthread_rwlock_wrlock(&stacknames_lock);
		refresh_stack_names();
		pthread_rwlock_unlock(&stacknames_lock);
		pthread_rwlock_rdlock(&stacknames_lock);
		stackname = stacknames[*stackid].s_stackname;
		stacknamelen = stacknames[*stackid].s_strlen;

		/*
		 * If we still don't have the stack name, just call it
		 * "unknown".
		 */
		if (stackname == NULL) {
			stackname = "unknown";
			stacknamelen = strlen(stackname);
		}
	}

	stacknamelen = strlen(stackname);
	opt = pcap_nflx_opt_alloc(NFLX_OPT_STACKNAME, stacknamelen + 1, false);
	if (opt == NULL)
		return (0);

	/* We allocated space. Mark the fact that we will need to clear it. */
	bit_set(free_map, *iovcnt);

	/* Update the IOV. */
	iov[*iovcnt].iov_base = opt;
	iov[*iovcnt].iov_len = sizeof(struct pcapng_nflx_opt);
	rv = iov[*iovcnt].iov_len;
	(*iovcnt)++;
	iov[*iovcnt].iov_base = stackid;
	iov[*iovcnt].iov_len = sizeof(*stackid);
	rv += iov[*iovcnt].iov_len;
	(*iovcnt)++;
	iov[*iovcnt].iov_base = __DECONST(void *, stackname);
	iov[*iovcnt].iov_len = stacknamelen;
	rv += iov[*iovcnt].iov_len;
	(*iovcnt)++;

	/* Pad, if necessary. */
	if (rv % 4) {
		iov[*iovcnt].iov_base = junk;
		iov[*iovcnt].iov_len = 4 - (rv % 4);
		rv += iov[*iovcnt].iov_len;
		(*iovcnt)++;
	}

	assert((rv % 4) == 0);
	return (rv);
}

/*
 * pcap_tcpbuf_opt() adds a custom option containing information about the current state
 * of the TCP stack.
 * This custom option is used in the enhanced packet block and also in the custom block
 * (the event block).
 */
static int
pcap_tcpbuf_opt(struct tcp_log_buffer *tlb, bool in_cb, struct iovec *iov, int *iovcnt,
    bitstr_t *free_map)
{
	void *opt;
	struct tcp_log_buffer *tlb_le;
#if (BYTE_ORDER == BIG_ENDIAN) && defined(NETFLIX_TCP_STACK)
	union tcp_log_userdata *tlu, *tlu_le;
	unsigned int i;
#endif
	int rv;

	opt = pcap_nflx_opt_alloc(NFLX_OPT_TCPINFO,
	    offsetof(struct tcp_log_buffer, tlb_th), in_cb);
	if (opt == NULL)
		return (0);

#if BYTE_ORDER == LITTLE_ENDIAN
	tlb_le = tlb;
#else
	tlb_le = malloc(sizeof(struct tcp_log_buffer));
	if (tlb_le == NULL) {
		warn("Error allocating space for the tcp_log_buffer");
		free(opt);
		return (0);
	}
	/* Convert all fields to litte endian. */
	tlb_le->tlb_tv.tv_sec = htole64(tlb->tlb_tv.tv_sec);
	tlb_le->tlb_tv.tv_usec = htole64(tlb->tlb_tv.tv_usec);
	tlb_le->tlb_ticks = htole32(tlb->tlb_ticks);
	tlb_le->tlb_sn = htole32(tlb->tlb_sn);
	tlb_le->tlb_stackid = tlb->tlb_stackid;
	tlb_le->tlb_eventid = tlb->tlb_eventid;
	tlb_le->tlb_eventflags = htole16(tlb->tlb_eventflags);
	tlb_le->tlb_errno = htole32(tlb->tlb_errno);
	tlb_le->tlb_rxbuf.tls_sb_acc = htole32(tlb->tlb_rxbuf.tls_sb_acc);
	tlb_le->tlb_rxbuf.tls_sb_ccc = htole32(tlb->tlb_rxbuf.tls_sb_ccc);
	tlb_le->tlb_rxbuf.tls_sb_spare = htole32(tlb->tlb_rxbuf.tls_sb_spare);
	tlb_le->tlb_txbuf.tls_sb_acc = htole32(tlb->tlb_txbuf.tls_sb_acc);
	tlb_le->tlb_txbuf.tls_sb_ccc = htole32(tlb->tlb_txbuf.tls_sb_ccc);
	tlb_le->tlb_txbuf.tls_sb_spare = htole32(tlb->tlb_txbuf.tls_sb_spare);
	tlb_le->tlb_state = htole32(tlb->tlb_state);
	tlb_le->tlb_starttime = htole32(tlb->tlb_starttime);
	tlb_le->tlb_iss = htole32(tlb->tlb_iss);
	tlb_le->tlb_flags = htole32(tlb->tlb_flags);
	tlb_le->tlb_snd_una = htole32(tlb->tlb_snd_una);
	tlb_le->tlb_snd_max = htole32(tlb->tlb_snd_max);
	tlb_le->tlb_snd_cwnd = htole32(tlb->tlb_snd_cwnd);
	tlb_le->tlb_snd_nxt = htole32(tlb->tlb_snd_nxt);
	tlb_le->tlb_snd_recover = htole32(tlb->tlb_snd_recover);
	tlb_le->tlb_snd_wnd = htole32(tlb->tlb_snd_wnd);
	tlb_le->tlb_snd_ssthresh = htole32(tlb->tlb_snd_ssthresh);
	tlb_le->tlb_srtt = htole32(tlb->tlb_srtt);
	tlb_le->tlb_rttvar = htole32(tlb->tlb_rttvar);
	tlb_le->tlb_rcv_up = htole32(tlb->tlb_rcv_up);
	tlb_le->tlb_rcv_adv = htole32(tlb->tlb_rcv_adv);
	tlb_le->tlb_flags2 = htole32(tlb->tlb_flags2);
	tlb_le->tlb_rcv_nxt = htole32(tlb->tlb_rcv_nxt);
	tlb_le->tlb_rcv_wnd = htole32(tlb->tlb_rcv_wnd);
	tlb_le->tlb_dupacks = htole32(tlb->tlb_dupacks);
	tlb_le->tlb_segqlen = htole32(tlb->tlb_segqlen);
	tlb_le->tlb_snd_numholes = htole32(tlb->tlb_snd_numholes);
	tlb_le->tlb_flex1 = htole32(tlb->tlb_flex1);
	tlb_le->tlb_flex2 = htole32(tlb->tlb_flex2);
	tlb_le->tlb_fbyte_in = htole32(tlb->tlb_fbyte_in);
	tlb_le->tlb_fbyte_out = htole32(tlb->tlb_fbyte_out);
	tlb_le->tlb_snd_scale = tlb->tlb_rcv_scale;
	tlb_le->tlb_rcv_scale = tlb->tlb_snd_scale;
	memcpy(tlb_le->_pad, tlb->_pad, 3);
	switch (tlb->tlb_eventid) {
#ifdef NETFLIX_TCP_STACK
	case TCP_LOG_SENDFILE:
		tlb_le->tlb_stackinfo.u_sf.offset =
		    htole64(tlb->tlb_stackinfo.u_sf.offset);
		tlb_le->tlb_stackinfo.u_sf.length =
		    htole64(tlb->tlb_stackinfo.u_sf.length);
		tlb_le->tlb_stackinfo.u_sf.flags =
		    htole32(tlb->tlb_stackinfo.u_sf.flags);
		/*
		 * Copy over the rest without modification, since the structure is not
		 * known. It should be padding.
		 */
		memcpy((char *)tlb_le + sizeof(struct tcp_log_sendfile),
		    (char *)tlb + sizeof(struct tcp_log_sendfile),
		    sizeof(union tcp_log_stackspecific) -
		    sizeof(struct tcp_log_sendfile));
		break;
	case TCP_LOG_USER_EVENT:
		tlu = (union tcp_log_userdata *)tlb;
		tlu_le = (union tcp_log_userdata *)tlb_le;
		switch (tlb->flex1) {
		case TCP_LOG_USER_HTTPD:
			tlu_le->http_req.timestamp = htole64(tlu_le->http_req.timestamp);
			tlu_le->http_req.start = htole64(tlu_le->http_req.start);
			tlu_le->http_req.end = htole64(tlu_le->http_req.end);
			tlu_le->http_req.flags = htole32(tlu_le->http_req.flags);
			/*
			 * Copy over the rest without modification, since the structure
			 * is not known. It should be padding.
			 */
			memcpy((char *)tlu_le + sizeof(union tcp_log_userdata),
			    (char *)tlu + sizeof(union tcp_log_userdata),
			    sizeof(union tcp_log_stackspecific) -
			    sizeof(union tcp_log_userdata));
			break;
		default:
			/*
			 * Copy over without modification, since the structure is not
			 * known.
			 */
			memcpy(tlu_le, tlu, sizeof(union tcp_log_stackspecific));
			break;
		}
		break;
	case TCP_LOG_ACCOUNTING:
		for (i = 0; i < 4; i++) {
			tlb_le->tlb_stackinfo.u_raw.u64_flex[i] =
			    htole64(tlb->tlb_stackinfo.u_raw.u64_flex[i]);
		}
		for (i = 0; i < 14; i++) {
			tlb_le->tlb_stackinfo.u_raw.u32_flex[i] =
			    htole32(tlb->tlb_stackinfo.u_raw.u32_flex[i]);
		}
		for (i = 0; i < 3; i++) {
			tlb_le->tlb_stackinfo.u_raw.u16_flex[i] =
			    htole16(tlb->tlb_stackinfo.u_raw.u16_flex[i]);
		}
		for (i = 0; i < 6; i++) {
			tlb_le->tlb_stackinfo.u_raw.u8_flex[i] =
			    tlb->tlb_stackinfo.u_raw.u8_flex[i];
		}
		tlb_le->tlb_stackinfo.u_raw.u32_flex2[0] =
		    htole32(tlb->tlb_stackinfo.u_raw.u32_flex2[0]);
		break;
#endif
	default:
		tlb_le->tlb_stackinfo.u_bbr.cur_del_rate =
		    htole64(tlb->tlb_stackinfo.u_bbr.cur_del_rate);
		tlb_le->tlb_stackinfo.u_bbr.delRate =
		    htole64(tlb->tlb_stackinfo.u_bbr.delRate);
		tlb_le->tlb_stackinfo.u_bbr.rttProp =
		    htole64(tlb->tlb_stackinfo.u_bbr.rttProp);
		tlb_le->tlb_stackinfo.u_bbr.bw_inuse =
		    htole64(tlb->tlb_stackinfo.u_bbr.bw_inuse);
		tlb_le->tlb_stackinfo.u_bbr.inflight =
		    htole32(tlb->tlb_stackinfo.u_bbr.inflight);
		tlb_le->tlb_stackinfo.u_bbr.applimited =
		    htole32(tlb->tlb_stackinfo.u_bbr.applimited);
		tlb_le->tlb_stackinfo.u_bbr.delivered =
		    htole32(tlb->tlb_stackinfo.u_bbr.delivered);
		tlb_le->tlb_stackinfo.u_bbr.timeStamp =
		    htole32(tlb->tlb_stackinfo.u_bbr.timeStamp);
		tlb_le->tlb_stackinfo.u_bbr.epoch =
		    htole32(tlb->tlb_stackinfo.u_bbr.epoch);
		tlb_le->tlb_stackinfo.u_bbr.lt_epoch =
		    htole32(tlb->tlb_stackinfo.u_bbr.lt_epoch);
		tlb_le->tlb_stackinfo.u_bbr.pkts_out =
		    htole32(tlb->tlb_stackinfo.u_bbr.pkts_out);
		tlb_le->tlb_stackinfo.u_bbr.flex1 =
		    htole32(tlb->tlb_stackinfo.u_bbr.flex1);
		tlb_le->tlb_stackinfo.u_bbr.flex2 =
		    htole32(tlb->tlb_stackinfo.u_bbr.flex2);
		tlb_le->tlb_stackinfo.u_bbr.flex3 =
		    htole32(tlb->tlb_stackinfo.u_bbr.flex3);
		tlb_le->tlb_stackinfo.u_bbr.flex4 =
		    htole32(tlb->tlb_stackinfo.u_bbr.flex4);
		tlb_le->tlb_stackinfo.u_bbr.flex5 =
		    htole32(tlb->tlb_stackinfo.u_bbr.flex5);
		tlb_le->tlb_stackinfo.u_bbr.flex6 =
		    htole32(tlb->tlb_stackinfo.u_bbr.flex6);
		tlb_le->tlb_stackinfo.u_bbr.lost =
		    htole32(tlb->tlb_stackinfo.u_bbr.lost);
		tlb_le->tlb_stackinfo.u_bbr.pacing_gain =
		    htole16(tlb->tlb_stackinfo.u_bbr.pacing_gain);
		tlb_le->tlb_stackinfo.u_bbr.cwnd_gain =
		    htole16(tlb->tlb_stackinfo.u_bbr.cwnd_gain);
		tlb_le->tlb_stackinfo.u_bbr.flex7 =
		    htole16(tlb->tlb_stackinfo.u_bbr.flex7);
		tlb_le->tlb_stackinfo.u_bbr.bbr_state =
		    tlb->tlb_stackinfo.u_bbr.bbr_state;
		tlb_le->tlb_stackinfo.u_bbr.bbr_substate =
		    tlb->tlb_stackinfo.u_bbr.bbr_substate;
		tlb_le->tlb_stackinfo.u_bbr.inhpts =
		    tlb->tlb_stackinfo.u_bbr.inhpts;
		tlb_le->tlb_stackinfo.u_bbr.ininput =
		    tlb->tlb_stackinfo.u_bbr.ininput;
		tlb_le->tlb_stackinfo.u_bbr.use_lt_bw =
		    tlb->tlb_stackinfo.u_bbr.use_lt_bw;
		tlb_le->tlb_stackinfo.u_bbr.flex8 =
		    tlb->tlb_stackinfo.u_bbr.flex8;
		tlb_le->tlb_stackinfo.u_bbr.pkt_epoch =
		    htole32(tlb->tlb_stackinfo.u_bbr.pkt_epoch);
		break;
	}
	tlb_le->tlb_len = htole32(tlb->tlb_len);
#endif

	/* Update the IOV. */
	iov[*iovcnt].iov_base = opt;
	iov[*iovcnt].iov_len = sizeof(struct pcapng_nflx_opt);
	rv = iov[*iovcnt].iov_len;
	bit_set(free_map, *iovcnt);
	(*iovcnt)++;
	iov[*iovcnt].iov_base = tlb_le;
	iov[*iovcnt].iov_len = offsetof(struct tcp_log_buffer, tlb_th);
	rv += iov[*iovcnt].iov_len;
#if BYTE_ORDER == BIG_ENDIAN
	bit_set(free_map, *iovcnt);
#endif
	(*iovcnt)++;

	return (rv);
}

static int
pcap_packetblock(struct tcp_log_buffer *buf, struct extract_context *ctx)
{
	struct pcapng_epb epb;
	struct pcapng_blockend epb_end;
	struct timeval utc_tv;
	struct ip *iphdr;
	struct ip6_hdr *ip6hdr;
	struct iovec iov[MAX_IOVS];
	bitstr_t bit_decl(free_map, MAX_IOVS);
	uint64_t ts;
	int data_len, hdr_len, iovcnt, pad_len, tcp_hlen, rv;

	/* Initialize free_map. */
	bit_nclear(free_map, 0, MAX_IOVS - 1);

	/* Initialize the enhanced packet block header. */
	epb.type = BT_EPB;
	epb.intid = 0;
	if (ctx->af == AF_INET)
		epb.protocol = PF_INET;
	else
		epb.protocol = PF_INET6;

	/* Get the UTC time. */
	timeradd(&buf->tlb_tv, ctx->tv_offset, &utc_tv);

	/*
	 * Timestamps are microseconds (by default) stored in two 32-bit
	 * fields representing the high and low bits.
	 */
	ts = (utc_tv.tv_sec * 1000000) + utc_tv.tv_usec;
	epb.ts_high = ts >> 32;
	epb.ts_low = ts & 0xffffffffUL;

	/* Set the IP addresses appropriately for the direction. */
	switch (buf->tlb_eventid) {
	case TCP_LOG_IN:
		/* Receive */
		if (ctx->af == AF_INET)
			iphdr = &ctx->in_iphdr;
		else
			ip6hdr = &ctx->in_ip6hdr;
		break;
	default:
		/* Send */
		if (ctx->af == AF_INET)
			iphdr = &ctx->out_iphdr;
		else
			ip6hdr = &ctx->out_ip6hdr;
		break;
	}

	/* Determine the TCP header length, IP length, and packet length. */
	tcp_hlen = buf->tlb_th.th_off << 2;
	data_len = tcp_hlen + buf->tlb_len;
	if (ctx->af == AF_INET) {
		data_len += sizeof(struct ip);
		iphdr->ip_len = htons(data_len);
		add_ip_cksum(iphdr);
	} else {
		ip6hdr->ip6_plen = htons(data_len);
		data_len += sizeof(struct ip6_hdr);
	}
	epb.pktlen = sizeof(uint32_t) + data_len;
	hdr_len = epb.pktlen - buf->tlb_len;

	/* Add the TCP checksum */
	add_tcp_cksum(ctx, &buf->tlb_th, tcp_hlen + buf->tlb_len);

	/*
	 * Assign the first IOVs. Overall layout looks like this:
	 * [0]: EPB (includes DLT_NULL header)
	 * [1]: IP HDR
	 * [2]: TCP HDR
	 * [3]: Padding (to the snaplen)
	 * [4]: EPB flags word option
	 * [5]: Option
	 * [n-1]: Options
	 * [n]: end-of-option-list option and total block length
	 */
	iov[0].iov_base = &epb;
	iov[0].iov_len = sizeof(epb);
	epb.len1 = iov[0].iov_len;
	if (ctx->af == AF_INET) {
		iov[1].iov_base = iphdr;
		iov[1].iov_len = sizeof(*iphdr);
	} else {
		iov[1].iov_base = ip6hdr;
		iov[1].iov_len = sizeof(*ip6hdr);
	}
	epb.len1 += iov[1].iov_len;
	iov[2].iov_base = &buf->tlb_th;
	iov[2].iov_len = tcp_hlen;
	epb.len1 += iov[2].iov_len;
	iovcnt = 3;

	/*
	 * Figure out the caplen and pad, if necessary.
	 *
	 * We pad for two reasons. First, we pad to add data, if any, from
	 * the packet that fits in the caplen. Second, we pad to hit a 32-bit
	 * boundary. Because the IP and TCP headers already fall on 32-bit
	 * boundaries, we only need to pad to the 32-bit boundary if we are
	 * adding data anyway.
	 */
	epb.caplen = min(epb.pktlen, MAX_SNAPLEN);
	pad_len = epb.caplen - hdr_len;
	assert(pad_len >= 0);
	if (pad_len > 0) {
		pad_len = ((pad_len + 3) / 4) * 4;
		iov[iovcnt].iov_base = junk;
		iov[iovcnt].iov_len = pad_len;
		epb.len1 += iov[iovcnt].iov_len;
		iovcnt++;
	}

	/* Add tcp info option. */
	epb.len1 += pcap_tcpbuf_opt(buf, false, iov, &iovcnt, free_map);

	/* Add an EPB flags word option to indicate the direction. */
	epb.len1 += pcap_epb_flags_opt(buf->tlb_eventid == TCP_LOG_IN, iov, &iovcnt,
	    free_map);

	/*
	 * Tack on the end of the block.
	 *
	 * The last option is always set to 0. We also need to
	 * record the block length at the end of the block.
	 */
	iov[iovcnt].iov_base = &epb_end;
	iov[iovcnt].iov_len = sizeof(epb_end);
	epb.len1 += iov[iovcnt].iov_len;
	iovcnt++;

	epb_end.lastopt = 0;
	epb_end.blocklen = epb.len1;
	assert(epb_end.blocklen % 4 == 0);

	assert(iovcnt <= MAX_IOVS);

	/* Write the block out. */
	rv = (*ctx->tcplog_writev)(ctx, iov, iovcnt, epb.len1);

	/* Free any memory we allocated. */
	free_iov_allocs(iov, iovcnt, free_map);

	return (rv);
}

static void
pcap_init_custom_block(struct pcapng_nflx_block *hdr, uint32_t type)
{
	hdr->type = BT_CB_COPY;
	hdr->pen = NFLX_PEN;
	hdr->nflx_type = htole32(type);
}

static int
pcap_eventblock(struct tcp_log_buffer *buf, struct extract_context *ctx)
{
	struct pcapng_nflx_eventblock eb;
	struct pcapng_blockend eb_end;
	struct iovec iov[MAX_IOVS];
	bitstr_t bit_decl(free_map, MAX_IOVS);
	int iovcnt, rv;

#ifdef DEBUG
	fprintf(stderr, "Creating event block for event %hhu\n", buf->tlb_eventid);
#endif

	/* Initialize free_map. */
	bit_nclear(free_map, 0, MAX_IOVS - 1);

	/* Initialize the event block header. */
	pcap_init_custom_block(&eb.hdr, NFLX_EVENT_BLOCK);
	iov[0].iov_base = &eb;
	iov[0].iov_len = sizeof(eb);
	eb.hdr.len1 = iov[0].iov_len;
	iovcnt = 1;

	/* Add tcp info option. */
	eb.hdr.len1 += pcap_tcpbuf_opt(buf, true, iov, &iovcnt, free_map);

	/*
	 * Tack on the end of the block.
	 *
	 * The last option is always set to 0. We also need to
	 * record the block length at the end of the block.
	 */
	iov[iovcnt].iov_base = &eb_end;
	iov[iovcnt].iov_len = sizeof(eb_end);
	eb.hdr.len1 += iov[iovcnt].iov_len;
	iovcnt++;

	eb_end.lastopt = 0;
	eb_end.blocklen = eb.hdr.len1;
	assert(eb_end.blocklen % 4 == 0);

	assert(iovcnt <= MAX_IOVS);

	/* Write the block out. */
	rv = (*ctx->tcplog_writev)(ctx, iov, iovcnt, eb.hdr.len1);

	/* Free any memory we allocated. */
	free_iov_allocs(iov, iovcnt, free_map);

	return (rv);
}

static int
pcap_skippedblock(struct extract_context *ctx, uint32_t num_skipped)
{
	struct pcapng_nflx_skipped sb;
	struct pcapng_blockend sb_end;
	struct iovec iov[2];

#ifdef DEBUG
	fprintf(stderr, "Creating skipped block for %u entries\n", num_skipped);
#endif

	/* Initialize the skipped block header. */
	pcap_init_custom_block(&sb.hdr, NFLX_SKIPPED_BLOCK);
	sb_end.blocklen = sb.hdr.len1 = sizeof(sb) + sizeof(sb_end);
	sb.num_skipped = htole32(num_skipped);
	iov[0].iov_base = &sb;
	iov[0].iov_len = sizeof(sb);

	/*
	 * Tack on the end of the block.
	 *
	 * The last option is always set to 0.
	 */
	sb_end.lastopt = 0;
	iov[1].iov_base = &sb_end;
	iov[1].iov_len = sizeof(sb_end);

	assert(sb_end.blocklen % 4 == 0);

	/* Write the block out. */
	return ((*ctx->tcplog_writev)(ctx, iov, 2, sb.hdr.len1));
}

static int
pcap_filestart(struct extract_context *ctx, struct tcp_log_header *hdr,
    uint8_t stackid, time_t *dumptime)
{
	struct pcapng_sh sh;
	struct pcapng_idb idb;
	struct pcapng_blockend idb_end, sh_end;
	struct iovec iov[MAX_IOVS];
	bitstr_t bit_decl(free_map, MAX_IOVS);
	int iovcnt, option_size, rv;

	/* Initialize free_map. */
	bit_nclear(free_map, 0, MAX_IOVS - 1);

	/* Add start of section header. */
	sh.type = BT_SHB;
	sh.hdrlen1 = sizeof(sh);
	sh.magic = MAGIC_NG;
	sh.major = MAJOR_NG;
	sh.minor = MINOR_NG;
	sh.seclen = -1;
	iov[0].iov_base = &sh;
	iov[0].iov_len = sizeof(sh);
	iovcnt = 1;

	/* Add netflix version option. */
	option_size = pcap_version_opt(iov, &iovcnt, free_map);
	if (option_size == 0)
		return (-1);
	sh.hdrlen1 += option_size;

	/* Add netflix dumptime option. */
	option_size = pcap_dumptime_opt(dumptime, iov, &iovcnt, free_map);
	if (option_size == 0) {
		rv = -1;
		goto done;
	}
	sh.hdrlen1 += option_size;

	/* Add netflix dumpinfo option. */
	option_size = pcap_dumpinfo_opt(hdr, iov, &iovcnt, free_map);
	if (option_size == 0) {
		rv = -1;
		goto done;
	}
	sh.hdrlen1 += option_size;

	/* Add netflix stack name option. */
	option_size = pcap_stackname_opt(&stackid, iov, &iovcnt, free_map);
	if (option_size == 0) {
		pthread_rwlock_unlock(&stacknames_lock);
		rv = -1;
		goto done;
	}
	sh.hdrlen1 += option_size;

	/* Add end of section header. */
	sh_end.lastopt = 0;
	sh.hdrlen1 += sizeof(sh_end);
	sh_end.blocklen = sh.hdrlen1;
	iov[iovcnt].iov_base = &sh_end;
	iov[iovcnt].iov_len = sizeof(sh_end);
	iovcnt++;

	/* Add start of interface description block. */
	idb.type = BT_IDB;
	idb.len1 = sizeof(idb);
	idb.linktype = DLT_NULL;
	idb.reserved = 0;
	idb.snaplen = MAX_SNAPLEN;
	iov[iovcnt].iov_base = &idb;
	iov[iovcnt].iov_len = sizeof(idb);
	iovcnt++;

	/* Add end of interface description block. */
	idb_end.lastopt = 0;
	idb.len1 += sizeof(idb_end);
	idb_end.blocklen = idb.len1;
	iov[iovcnt].iov_base = &idb_end;
	iov[iovcnt].iov_len = sizeof(idb_end);
	iovcnt++;

	assert(iovcnt <= MAX_IOVS);

	/* Write all of this out. */
	rv = (*ctx->tcplog_writev)(ctx, iov, iovcnt, sh.hdrlen1 + idb.len1);

	/* Release the lock we held on the stack names. */
	pthread_rwlock_unlock(&stacknames_lock);
done:
	/* Free allocated memory. */
	free_iov_allocs(iov, iovcnt, free_map);

	return (rv);
}

static ssize_t
refill_input(int fd, void *buf, ssize_t minbytes, size_t maxbytes)
{
	uint8_t *curp;
	ssize_t bytes_read, read_rv;

	curp = (uint8_t *)buf;
	bytes_read = 0;
	do {
		read_rv = read(fd, curp, maxbytes);
		if (read_rv == 0)
			break;
		if (read_rv < 0 && !(errno == EINTR || errno == EAGAIN))
			return (bytes_read ?: -1);
		if (read_rv > 0) {
			curp += read_rv;
			minbytes -= read_rv;
			maxbytes -= read_rv;
			bytes_read += read_rv;
		}
	} while (!quit_requested && minbytes > 0 && maxbytes);
	return bytes_read;
}

static void
init_extract_context(struct extract_context *ctx, struct tcp_log_header *hdr,
    int fd)
{

	ctx->out_fd = fd;
	ctx->tv_offset = &hdr->tlh_offset;

	/* Initialize the IP/IP6 header. */
	ctx->af = hdr->tlh_af;
	switch (ctx->af) {
	case AF_INET:
		/* Initialize the incoming header. */
		memset(&ctx->in_iphdr, 0, sizeof(struct ip));
		ctx->in_iphdr.ip_v = IPVERSION;
		ctx->in_iphdr.ip_hl = sizeof(struct ip) >> 2;
		ctx->in_iphdr.ip_ttl = 127;
		ctx->in_iphdr.ip_p = IPPROTO_TCP;

		/* Copy the incoming header to the outgoing header. */
		ctx->out_iphdr = ctx->in_iphdr;

		/* Fill in the appropriate addresses for each direction. */
		ctx->in_iphdr.ip_src = hdr->tlh_ie.ie_faddr;
		ctx->in_iphdr.ip_dst = hdr->tlh_ie.ie_laddr;
		ctx->out_iphdr.ip_src = hdr->tlh_ie.ie_laddr;
		ctx->out_iphdr.ip_dst = hdr->tlh_ie.ie_faddr;
		break;
	case AF_INET6:
		/* Initialize the incoming header. */
		memset(&ctx->in_ip6hdr, 0, sizeof(struct ip6_hdr));
		ctx->in_ip6hdr.ip6_vfc = IPV6_VERSION;
		ctx->in_ip6hdr.ip6_nxt = IPPROTO_TCP;
		ctx->in_ip6hdr.ip6_hlim = 127;

		/* Copy the incoming header to the outgoing header. */
		ctx->out_ip6hdr = ctx->in_ip6hdr;

		/* Fill in the appropriate addresses for each direction. */
		ctx->in_ip6hdr.ip6_src = hdr->tlh_ie.ie6_faddr;
		ctx->in_ip6hdr.ip6_dst = hdr->tlh_ie.ie6_laddr;
		ctx->out_ip6hdr.ip6_src = hdr->tlh_ie.ie6_laddr;
		ctx->out_ip6hdr.ip6_dst = hdr->tlh_ie.ie6_faddr;
		break;
	}

	/* Do extra initialization work for the write method. */
	switch (compression) {
	case COMPRESSION_XZ:
		tcplog_xz_init(ctx);
		break;

	default:
		ctx->tcplog_writev = writev_int;
		ctx->ctx_fini = NULL;
		break;
	}
}

static void
fini_extract_context(struct extract_context *ctx)
{

	/* Do any extra finalization work. */
	if (ctx->ctx_fini != NULL)
		(*ctx->ctx_fini)(ctx);

	/* Close the file descriptor. */
	if (ctx->out_fd >= 0) {
		close(ctx->out_fd);
		ctx->out_fd = -1;
	}
}

static void
escape(const char *in, char *out, int outsz)
{
	char *end;
	char ch;

	end = out + (outsz - 2);
	while (out < end && (ch = *in++) != '\0') {
		if (isspace(ch))
			*out++ = ' ';
		else if (ch == '\"' || ch == '\\') {
			*out++ = '\\';
			*out++ = ch;
		} else if (isprint(ch))
			*out++ = ch;
		else
			*out++ = '?';
	}
	*out = '\0';
}

#define	DATESTRSZ	64
#define	LOGBUFSZ	1024
static void
log_record(int dirfd, char *file_name, char *faddr, struct tcp_log_header *hdr,
    uint32_t cnt, time_t dumptime, uint8_t stackid, struct timeval *start_tv,
    struct timeval *last_tv, bool conn_end, int file_no)
{
	struct timeval duration_tv;
        char buf[LOGBUFSZ], datestr[DATESTRSZ], laddr[INET6_ADDRSTRLEN];
	char id[TCP_LOG_ID_LEN * 2], tag[TCP_LOG_TAG_LEN * 2];
	char reason[TCP_LOG_REASON_LEN * 2];
	char *curp;
	int outsz, writerv;
	static int log_fd = -1;

	pthread_mutex_lock(&log_record_mutex);

	/* Check for a SIGHUP. */
	if (reset_log_file) {
		close(log_fd);
		log_fd = -1;
		reset_log_file = false;
	}

	/* Open the log device. */
	if (log_fd < 0) {
		log_fd = openat(dirfd, "records",
		    O_WRONLY | O_CREAT | O_APPEND,
		    S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		if (log_fd < 0)
			goto done;
	}
	/* Get the local address. */
	switch (hdr->tlh_af) {
	case AF_INET:
		if (inet_ntop(AF_INET, &hdr->tlh_ie.ie_laddr, laddr,
		    INET6_ADDRSTRLEN) == NULL)
			strcpy(laddr, "(unknown)");
		break;
	case AF_INET6:
		if (inet_ntop(AF_INET6, &hdr->tlh_ie.ie6_laddr, laddr,
		    INET6_ADDRSTRLEN) == NULL)
			strcpy(laddr, "(unknown)");
		break;
	default:
		strcpy(laddr, "(unknown)");
		break;
	}

	/* Get the time. */
	if (dumptime == (-1) ||
	    !strftime(datestr, DATESTRSZ, "%F %T %z", gmtime(&dumptime)))
		strcpy(datestr, "unknown");

	/* Get the ID. Ensure it is NULL-terminated. */
	hdr->tlh_id[TCP_LOG_ID_LEN - 1] = '\0';
	escape(hdr->tlh_id, id, sizeof(id));

	/* Get the tag. Ensure it is NULL-terminated. */
	hdr->tlh_tag[TCP_LOG_TAG_LEN - 1] = '\0';
	escape(hdr->tlh_tag, tag, sizeof(tag));

	/* Get the reason. Ensure it is NULL-terminated. */
	hdr->tlh_reason[TCP_LOG_REASON_LEN - 1] = '\0';
	escape(hdr->tlh_reason, reason, sizeof(reason));

	/* Get the duration. */
	if (timercmp(start_tv, last_tv, <))
		timersub(last_tv, start_tv, &duration_tv);
	else
		timerclear(&duration_tv);

	/* Write out the record. */
	pthread_rwlock_rdlock(&stacknames_lock);
	outsz = snprintf(buf, LOGBUFSZ, "{\"date\":\"%s\", \"pbcid\":\"%s\", "
	    "\"reason\":\"%s\", \"faddr\":\"%s\", \"fport\":%hu, "
	    "\"laddr\":\"%s\", \"lport\":%hu, \"filename\":\"%s\", "
	    "\"record_count\":%u, \"stack\":\"%s\", \"duration\":%ld.%06ld, "
	    "\"connection_ended\":%s, \"tag\":\"%s\", \"compressor\":\"%s\", "
	    "\"frag_seq\":%d}\n",
	    datestr, id, reason, faddr, ntohs(hdr->tlh_ie.ie_fport), laddr,
	    ntohs(hdr->tlh_ie.ie_lport), file_name, cnt,
	    stacknames[stackid].s_stackname ?: "unknown",
	    (long)duration_tv.tv_sec, duration_tv.tv_usec,
	    conn_end ? "true" : "false", tag,
	    (compression == COMPRESSION_XZ) ? "xz" : "", file_no);
	pthread_rwlock_unlock(&stacknames_lock);

	/* Make sure the line isn't too long. */
	if (outsz >= LOGBUFSZ)
		goto done;

	/*
	 * Write this out. In theory, we shouldn't have short writes, but there
	 * is no reason we can't deal with this.
	 */
	curp = buf;
	while (outsz) {
		writerv = write(log_fd, curp, outsz);
		if (writerv < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (writerv <= 0)
			goto done;
		curp += writerv;
		outsz -= writerv;
	}

done:
	pthread_mutex_unlock(&log_record_mutex);
}

static int
open_bbr_file(int dirfd, struct tcp_log_header *hdr, char *out_file,
    char *faddr, int *file_no)
{
	int *next_filenum;
	char session_id[PATH_MAX];
	int fd, i, limit;

	/* Get the foreign address. */
	switch (hdr->tlh_af) {
	case AF_INET:
		if (inet_ntop(AF_INET, &hdr->tlh_ie.ie_faddr, faddr,
		    INET6_ADDRSTRLEN) == NULL)
			strcpy(faddr, "(unknown)");
		break;
	case AF_INET6:
		if (inet_ntop(AF_INET6, &hdr->tlh_ie.ie6_faddr, faddr,
		    INET6_ADDRSTRLEN) == NULL)
			strcpy(faddr, "(unknown)");
		break;
	default:
		/* Unknown address family. This is doomed. */
		log_message(LOG_INFO, "Skipping black box record with unknown "
		    "address family %hhu", hdr->tlh_af);
		return (-1);
	}

	/* Get the unique session identifier. */
	if (snprintf(session_id, PATH_MAX, "%s_%hu_%s_%hu",
	    hdr->tlh_id, ntohs(hdr->tlh_ie.ie_lport), faddr,
	    ntohs(hdr->tlh_ie.ie_fport)) >= PATH_MAX) {
		log_message(LOG_INFO, "Skipping black box record: "
		    "identifier for filename is too long");
		return (-1);
	}

	/* Look up the identifier in the thread-specific cache. */
	next_filenum = idcache_get(session_id);
	i = (next_filenum != NULL) ? *next_filenum : 0;

	/* Pick a filename. */
	for (limit = (i + 1024); i < limit; i++) {
		if (snprintf(out_file, PATH_MAX, "%s.%d.pcapng%s",
		    session_id, i,
		    (compression == COMPRESSION_XZ) ? ".xz" : "") >= PATH_MAX) {
			log_message(LOG_INFO, "Skipping black box record: "
			    "filename is too long");
			return (-1);
		}
		fd = openat(dirfd, out_file, O_WRONLY | O_CREAT | O_EXCL,
		    S_IRUSR | S_IRGRP | S_IROTH);
		if (fd >= 0)
			break;
	}
	if (fd < 0)
		warn("Unable to open file to write black box record");
	else {
		*file_no = i;

		/*
		 * If the ID was already in the cache, update the
		 * cached next_filenum.  If the ID wasn't in the
		 * cache, add it unless the reason looks like a
		 * one-time event.
		 */
		if (next_filenum != NULL)
			*next_filenum = i + 1;
		else if (memcmp(hdr->tlh_reason, "error", 6) &&
		    memcmp(hdr->tlh_reason, "rebuffer", 9))
			idcache_add(session_id, i + 1);
	}
	return (fd);
}

static void
do_bbr_record(int dirfd, struct tcp_log_header *hdr)
{
	struct extract_context ctx;
	struct timeval last_tv, start_tv;
	struct tcp_log_buffer *record;
	uint64_t record_len;
	time_t now;
	uint32_t last_sn, record_count;
	int file_no, out_fd, write_rv;
	bool conn_end, first_record;
	char faddr[INET6_ADDRSTRLEN], out_file[PATH_MAX];
	uint8_t stackid;

	/* Determine the length of the body. Skip empty messages. */
	hdr->tlh_length -= sizeof(*hdr);
	if (hdr->tlh_length < sizeof(*record)) {
		log_message(LOG_ERR, "Incorrect header length while "
		    "starting to process black box record");
		return;
	}

	/* Get the current time. */
	(void)time(&now);

	/* Find the first record. */
	record = (struct tcp_log_buffer *)(hdr + 1);

restart:
	/* Get our output file descriptor or skip the record. */
	if ((out_fd = open_bbr_file(dirfd, hdr, out_file, faddr, &file_no)) < 0)
		return;

	/*
	 * Initialize the context and then print the header. If that fails,
	 * skip the record.
	 */
	init_extract_context(&ctx, hdr, out_fd);
	if (pcap_filestart(&ctx, hdr, record->tlb_stackid, &now)) {
		fini_extract_context(&ctx);
		unlinkat(dirfd, out_file, 0);
		return;
	}

	/* Iterate through the records. */
	conn_end = false;
	first_record = true;
	record_count = 0;
	while (hdr->tlh_length) {
		record_len = sizeof(*record);
		if (hdr->tlh_length < record_len) {
			log_message(LOG_ERR, "Incorrect header length while "
			    "processing black box record");
			fini_extract_context(&ctx);
			if (first_record)
				unlinkat(dirfd, out_file, 0);
			return;
		}

		/* The first time through, see if we need to get more. */
		if (record->tlb_eventflags & TLB_FLAG_VERBOSE) {
			record_len += sizeof(struct tcp_log_verbose);
			if (hdr->tlh_length < record_len) {
				log_message(LOG_ERR, "Incorrect header length "
				    "while processing verbose black box "
				    "record");
				fini_extract_context(&ctx);
				if (first_record)
					unlinkat(dirfd, out_file, 0);
				unlinkat(dirfd, out_file, 0);
				return;
			}
		}
		if (first_record) {
			last_sn = record->tlb_sn;
			first_record = false;
			stackid = record->tlb_stackid;
			start_tv = record->tlb_tv;
		} else {
			if (stackid != record->tlb_stackid) {
				/*
				 * We switched stacks. Close the current output
				 * file and create a new one for the new stack.
				 */
				fini_extract_context(&ctx);
				log_record(dirfd, out_file, faddr, hdr,
				    record_count, now, stackid, &start_tv,
				    &last_tv, conn_end, file_no);
				goto restart;
			}
			if (++last_sn != record->tlb_sn) {
				(void)pcap_skippedblock(&ctx,
				    record->tlb_sn - last_sn);
				last_sn = record->tlb_sn;
			}
		}
		last_tv = record->tlb_tv;

		/*
		 * If the record has a packet, dump the packet.
		 * Otherwise, record the event.
		 */
		if (record->tlb_eventflags & TLB_FLAG_HDR)
			write_rv = pcap_packetblock(record, &ctx);
		else {
			write_rv = pcap_eventblock(record, &ctx);
			if (record->tlb_eventid == TCP_LOG_CONNEND)
				conn_end = true;
		}
		record_count++;

		/*
		 * If we encounter errors writing, we'll just give up. They
		 * are pretty much all likely to be fatal at this point
		 * anyway.
		 */
		if (write_rv) {
			fini_extract_context(&ctx);
			if (first_record)
				unlinkat(dirfd, out_file, 0);
			return;
		}

		/* Next record. */
		assert(hdr->tlh_length >= record_len);
		hdr->tlh_length -= record_len;
		/* Check alignment, which we will override in the next line. */
		assert(record_len % __alignof__(struct tcp_log_buffer) == 0);
		record = (void *)(((uint8_t *)record) + record_len);
	}

	/* Finalize the extract context (which also closes the output fd). */
	fini_extract_context(&ctx);

	/*
	 * If we obtained a minimal number of records, or this not a
	 * client-signalled error, then record it. Otherwise, drop it.
	 */
	if (record_count > 10 || (strcmp(hdr->tlh_reason, "error") &&
	    strcmp(hdr->tlh_reason, "rebuffer")))
		log_record(dirfd, out_file, faddr, hdr, record_count, now,
		    stackid, &start_tv, &last_tv, conn_end, file_no);
	else
		unlinkat(dirfd, out_file, 0);

	/* Figure out how much of the buffer is left. We consumed the rest. */
	return;
}

/* Block all signals from threads other than the main one. */
static void
block_signals(void)
{
	sigset_t sigmask;

	sigfillset(&sigmask);
	pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
}

/*
 * Check for ID expiry roughly every 30 seconds or 100 records.
 */
#define	EXPIRY_CHECK_INTVL_TIME	30
#define	EXPIRY_CHECK_INTVL_RECS	100

static void *
bbr_worker_thread(void *arg)
{
	struct loghead *qhead;
	pthread_mutex_t *qmtx;
	pthread_cond_t *qcond;
	struct log_queue *lq;
	struct timespec ts;
	int queue, reccount;

	/* Setup signals. */
	block_signals();

	/* Get the queue number from the argument. */
	assert(arg != NULL);
	queue = *(int *)arg;
	free(arg);

	/* Get the correct structures for our queue. */
	qhead = &bbr_loghead[queue];
	qmtx = &bbr_queue_mtx[queue];
	qcond = &bbr_queue_cond[queue];

	/* Initialize the ID cache. */
	idcache_init(queue);
	reccount = 0;

	/* Initialize the expiry timer. */
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += EXPIRY_CHECK_INTVL_TIME;

	/* Enter a continuous loop to do our work. */
	pthread_mutex_lock(qmtx);
	while (!quit_requested) {
		lq = STAILQ_FIRST(qhead);
		if (lq == NULL) {
			if (pthread_cond_timedwait(qcond, qmtx, &ts)) {
				pthread_mutex_unlock(qmtx);
				idcache_expire();
				reccount = 0;
				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_sec += EXPIRY_CHECK_INTVL_TIME;
				pthread_mutex_lock(qmtx);
			}
			continue;
		}
		STAILQ_REMOVE_HEAD(qhead, lq_link);
		pthread_mutex_unlock(qmtx);

		do_bbr_record(lq->lq_dirfd,
		    (struct tcp_log_header *)lq->lq_log);
		free(lq->lq_log);
		free(lq);
		if (atomic_fetchadd_int(&queued_records, -1) ==
		    QUEUED_RECORDS_LOWAT) {
			/*
			 * The queue count just dropped below the low water
			 * mark. Wake the reader thread up so it can do work
			 * again.
			 */
			pthread_mutex_lock(&queuewait_mutex);
			pthread_cond_signal(&queuewait_cond);
			pthread_mutex_unlock(&queuewait_mutex);
		}
		if (reccount < (EXPIRY_CHECK_INTVL_RECS - 1))
			reccount++;
		else {
			idcache_expire();
			reccount = 0;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += EXPIRY_CHECK_INTVL_TIME;
		}
		pthread_mutex_lock(qmtx);
	}
	pthread_mutex_unlock(qmtx);
	return (NULL);
}

static void
start_threads(void)
{
	int queue;
	int *queuep;

	/* Record the main thread's TID. */
	main_thread_tid = pthread_self();


	/* Initialize the queue-waiting mutex and condition. */
	if (pthread_mutex_init(&queuewait_mutex, NULL) ||
	    pthread_cond_init(&queuewait_cond, NULL)) {
		fprintf(stderr, "Error initializing the queue-waiting "
		    "structures\n");
		do_exit(1);
	}

	/* Initialize the log record mutex. */
	if (pthread_mutex_init(&log_record_mutex, NULL) != 0) {
		fprintf(stderr, "Error initializing the log record mutex\n");
		do_exit(1);
	}

	/*
	 * Initialize the data structures for each BBR log worker thread and
	 * start the thread.
	 */
	for (queue = 0; queue < NUM_THREADS; queue++) {
		queuep = malloc(sizeof(int));
		if (queuep == NULL)
			do_err(1, "Error allocating memory for thread %d "
			    "argument", queue);
		*queuep = queue;
		STAILQ_INIT(&bbr_loghead[queue]);
		if (pthread_mutex_init(&bbr_queue_mtx[queue], NULL) ||
		    pthread_cond_init(&bbr_queue_cond[queue], NULL)) {
			fprintf(stderr, "Error initializing pthread structures "
			    "for thread %d\n", queue);
			do_exit(1);
		}
		if (pthread_create(&bbr_tid[queue], NULL, bbr_worker_thread,
		    queuep)) {
			fprintf(stderr, "Error creating thread %d\n", queue);
			do_exit(1);
		}
		bbr_threads++;
	}
}

static __inline int
hash_bbr_record(struct tcp_log_header *hdr)
{

	return (((int)hdr->tlh_ie.ie_fport + (int) hdr->tlh_ie.ie_lport) %
	    NUM_THREADS);
}

static void
dispatch_bbr_record(struct tcp_log_header *hdr, int dirfd)
{
	struct log_queue *lq;
	int queue;

	/* Prepare the log queue entry. */
	lq = malloc(sizeof(struct log_queue));
	if (lq == NULL)
		do_err(1, "Error allocating log queue entry");
	lq->lq_log = hdr;
	lq->lq_dirfd = dirfd;

	/* Pick a queue and add this entry to the correct queue. */
	queue = hash_bbr_record(hdr);
	pthread_mutex_lock(&bbr_queue_mtx[queue]);
	STAILQ_INSERT_TAIL(&bbr_loghead[queue], lq, lq_link);
	pthread_cond_signal(&bbr_queue_cond[queue]);
	pthread_mutex_unlock(&bbr_queue_mtx[queue]);
}

static const char *reason_must_be = NULL;
static int32_t reason_len = 0;


static void
do_loop(int dirfd, int fd)
{
	void *curp, *inbuf;
	struct tcp_log_common_header hdr;
	struct tcp_log_header *lh;
	struct timespec ts;
	ssize_t bytes_need, bytes_read;
	int alignment;
	bool added_record;

	/*
	 * Determine the lowest alignment requirement that will satisfy all
	 * the data structures. (At the moment, that is easy, since there
	 * is only one.)
	 */
	alignment = __alignof__(struct tcp_log_header);

	/* Do loop. */
	while (!quit_requested) {
		bytes_read = refill_input(fd, &hdr, sizeof(hdr), sizeof(hdr));
		/* Check for EOF. */
		if (bytes_read == 0)
			do_exit(0);
		/* Check for a read error. */
		if (bytes_read < 0)
			do_err(1, "Error reading input");
		/* Check for a short read. */
		if (bytes_read < (ssize_t)sizeof(hdr)) {
			fprintf(stderr, "Error reading log header: "
			    "received %zu bytes, expected %zu bytes\n",
			    bytes_read, sizeof(hdr));
			do_exit(1);
		}

		/* Allocate a buffer and read the message. */
		inbuf = aligned_alloc(alignment,
		    roundup2(hdr.tlch_length, alignment));
		if (inbuf == NULL)
			do_err(1, "Error allocating buffer for log message");
		memcpy(inbuf, &hdr, sizeof(hdr));
		curp = ((uint8_t *)inbuf) + sizeof(hdr);

		bytes_need = hdr.tlch_length - sizeof(hdr);
		assert(bytes_need >= 0);
		if (bytes_need > 0) {
			bytes_read = refill_input(fd, curp, bytes_need,
			    bytes_need);

			/* Check for various read problems. */
			if (bytes_read < 0)
				do_err(1, "Error reading input");
			if (bytes_read < bytes_need) {
				fprintf(stderr, "Error reading log message: "
				    "received %zu bytes, expected %zu bytes\n",
				    bytes_read, bytes_need);
				do_exit(1);
			}
		}

		switch (hdr.tlch_type) {
		case TCP_LOG_DEV_TYPE_BBR:
			/* Add this to the queue for the thread pool. */
			lh = (struct tcp_log_header *)inbuf;
			if (reason_must_be &&
			    (strncasecmp(lh->tlh_reason, reason_must_be, reason_len) != 0)) {
				/* 
				 * The reason does not match our required reason 
				 * skip this record.
				 */
				log_message(LOG_INFO, "Skipping record of non matching reason"
					    "%s", lh->tlh_reason);

				free(inbuf);
				added_record = false;
				break;
			}
			dispatch_bbr_record(inbuf, dirfd);
			added_record = true;
			break;

		default:
			log_message(LOG_INFO, "Skipping record of unknown type "
			    "%u", hdr.tlch_type);
			free(inbuf);
			added_record = false;
			break;
		}
		if (added_record && atomic_fetchadd_int(&queued_records, 1) ==
		    QUEUED_RECORDS_HIWAT && !quit_requested) {
			/*
			 * We just went over the high-water mark.
			 * Sleep for up to two seconds at a time while
			 * we wait for this to drop below the
			 * low-water mark.
			 */
			pthread_mutex_lock(&queuewait_mutex);
			while (!quit_requested &&
			    atomic_fetchadd_int(&queued_records, 0) >=
			    QUEUED_RECORDS_LOWAT) {
				clock_gettime(CLOCK_REALTIME, &ts);
				ts.tv_sec += 2;
				pthread_cond_timedwait(&queuewait_cond,
				    &queuewait_mutex, &ts);
			}
			pthread_mutex_unlock(&queuewait_mutex);
		}
	}
}

static void usage(char *prog) __attribute__ ((noreturn));
static void usage(char *prog)
{
	fprintf(stderr, "%s [-dhJ] [-D dir] [-f file] [-u user] [-r reason]\n", prog);
	fprintf(stderr, "\n"
	    "  -d: Daemonize the process.\n"
	    "  -h: Display this help message.\n"
	    "  -J: Compress the output using the XZ format.\n"
	    "  -D: Store the files in the given base directory. (Default: %s)\n"
	    "  -f: Read from the given file. (Default: %s)\n"
	    "  -u: Use the UID of the given username. (Default: %s)\n"
	    "  -r reason: only write records of type reason\n"
	    "\n", default_directory, default_filename, default_username);

	exit(1);
}

static bool
check_perms(int dirfd, uid_t uid, gid_t gid)
{
	struct stat sb;

	if (fstat(dirfd, &sb))
		err(1, "Error getting directory permissions");
	if (!S_ISDIR(sb.st_mode))
		return false;
	if (uid == sb.st_uid &&
	    (sb.st_mode & (S_IWUSR | S_IXUSR)) == (S_IWUSR | S_IXUSR))
		return true;
	else if (uid == sb.st_uid)
		return false;
	if (gid == sb.st_gid &&
	    (sb.st_mode & (S_IWGRP | S_IXGRP)) == (S_IWGRP | S_IXGRP))
		return true;
	else if (gid == sb.st_gid)
		return false;
	if ((sb.st_mode & (S_IWOTH | S_IXOTH)) == (S_IWOTH | S_IXOTH))
		return true;
	return false;
}

static void
version_check(void)
{
	size_t sz;
	uint32_t version;

	sz = sizeof(version);
	if (sysctlbyname("net.inet.tcp.bb.log_version", &version, &sz, NULL, 0))
		err(1, "Error retrieving TCP log version from kernel");

	if (version != TCP_LOG_BUF_VER) {
		fprintf(stderr, "Error: tcp log version mismatch (kernel reports "
		    "%u; expected %u)\n", version, TCP_LOG_BUF_VER);
		exit(1);
	}
}

static void
setup_signal_handlers(void)
{

	signal(SIGHUP, process_sighup);
	siginterrupt(SIGINT, 1);
	signal(SIGINT, process_sigterm);
	siginterrupt(SIGTERM, 1);
	signal(SIGTERM, process_sigterm);
	signal(SIGUSR1, SIG_IGN);
	siginterrupt(SIGUSR2, 1);
	signal(SIGUSR2, process_sigusr2);
}

static void
save_pid(int fd)
{
	FILE *pid_file;

	if (fd < 0)
		return;
	pid_file = fdopen(fd, "w");
	if (pid_file == NULL) {
		warn("Error opening PID file object");
		close(fd);
		return;
	}
	if (fprintf(pid_file, "%d\n", getpid()) < 0)
		log_message(LOG_ERR, "Error writing to PID file");
	fclose(pid_file);
}

int
main(int argc, char *argv[])
{
	struct passwd *userpasswd;
	const char *directory, *filename, *pid_filename, *username;
	pid_t child;
	int dirfd, fd, opt, pidfd;
	bool daemonize;

	version_check();
	setup_signal_handlers();

	daemonize = false;
	directory = default_directory;
	filename = default_filename;
	pid_filename = NULL;
	username = default_username;
	while ((opt = getopt(argc, argv, ":D:df:hJp:u:r:")) != -1)
		switch (opt) {
		case 'r':
			reason_must_be = optarg;
			reason_len = strlen(reason_must_be);
			break;
		case 'D':
			directory = optarg;
			break;

		case 'd':
			daemonize = true;
			break;

		case 'f':
			filename = optarg;
			break;

		case 'h':
			usage(*argv);

		case 'J':
			compression = COMPRESSION_XZ;
			break;

		case 'p':
			pid_filename = optarg;
			break;

		case 'u':
			username = optarg;
			break;
			
		case ':':
			fprintf(stderr, "Option -%c requires an argument.\n",
			    (char)optopt);
			usage(*argv);

		default:
			fprintf(stderr, "Unknown option -%c.\n", (char)optopt);
			usage(*argv);
		}

	/* Open the input file and PID file and then drop privileges. */
	if ((fd = open(filename, O_RDONLY)) < 0)
		err(1, "Error opening %s", filename);
	if (pid_filename != NULL) {
		pidfd = open(pid_filename, O_WRONLY | O_TRUNC | O_CREAT,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if (pidfd < 0)
			err(1, "Error opening PID file %s", filename);
	} else
		pidfd = -1;

	errno = 0;
	if ((userpasswd = getpwnam(username)) == NULL && errno)
		err(1, "Error finding user \"%s\"", username);
	else if (userpasswd == NULL) {
		fprintf(stderr, "Error finding user \"%s\": no such user\n",
		    username);
		return (1);
	}
	setgid(userpasswd->pw_gid);
	setuid(userpasswd->pw_uid);

	/* Now, open the output directory. */
	if ((dirfd = open(directory, O_RDONLY | O_DIRECTORY)) < 0)
		err(1, "Error opening directory \"%s\"", directory);

	/* Check permissions. */
	if (!check_perms(dirfd, userpasswd->pw_uid, userpasswd->pw_gid)) {
		fprintf(stderr, "It appears user \"%s\" does not have "
		    "permission to write to directory %s.\n", username,
		    directory);
		return (1);
	}

	/* Initialize our padding space. */
	memset(junk, 0, MAX_SNAPLEN);

	/* Initialize the stack names. */
	init_stack_names();

	/* Become a daemon if requested. */
	if (daemonize) {
		if ((child = fork()) == -1)
			err(1, "Error forking child");
		if (child) {
			/* We are the parent. */
			return (0);
		}
	}

	/* Write out PID. */
	save_pid(pidfd);

	/* Start threads. */
	start_threads();

	/* Do loop. */
	do_loop(dirfd, fd);

	return (exit_code);
}
