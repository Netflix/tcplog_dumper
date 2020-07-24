/*-
 * Copyright (c) 2017
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

#include <sys/cdefs.h>
#include <sys/queue.h>
#include <sys/stddef.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tcplog_dumper.h"

/* The number of seconds we cache entries. */
#define	EXPIRY_TIME	(5 * 60)

RB_HEAD(id_tree, id_record);
static struct id_tree id_tree_head[NUM_THREADS];
TAILQ_HEAD(expiryq, id_record);
static struct expiryq expiryq_head[NUM_THREADS];
static _Thread_local int tdidx;

struct id_record {
	char			*id;
	RB_ENTRY(id_record)	treenode;
	TAILQ_ENTRY(id_record)	tq;
	time_t			last_used;
	int			next_filenum;
};

RB_PROTOTYPE_STATIC(id_tree, id_record, treenode, id_cmp)

/*
 * Ensure we can directly compare keys using (char **) and
 * (struct id_record *).
 */
_Static_assert(offsetof(struct id_record, id) == 0,
    "id must be the first field in (struct id_record)");

static inline int
id_cmp(struct id_record *a, struct id_record *b)
{

	return (strcmp(a->id, b->id));
}

RB_GENERATE_STATIC(id_tree, id_record, treenode, id_cmp)

/*
 * Initialize the idcache for a thread.
 *
 * This also sets the thread index, which we hold in thread-local storage
 * and use as an index into our arrays.
 *
 * Arguments:
 * - The thread index.
 */
void
idcache_init(int idx)
{

	assert(idx < NUM_THREADS);
	tdidx = idx;
	RB_INIT(&id_tree_head[idx]);
	TAILQ_INIT(&expiryq_head[idx]);
}

/*
 * Check the expiry queue for a thread.
 *
 * The calling threads should run this periodically to clean up their
 * expired ID entries.
 */
void
idcache_expire(void)
{
	struct id_record *idr;
	time_t expirytime;

	expirytime = time(NULL) - EXPIRY_TIME;

	while ((idr = TAILQ_FIRST(&expiryq_head[tdidx])) != NULL) {
		if (idr->last_used > expirytime)
			break;
		TAILQ_REMOVE(&expiryq_head[tdidx], idr, tq);
		RB_REMOVE(id_tree, &id_tree_head[tdidx], idr);
		free(idr->id);
		free(idr);
	}
}

/*
 * Add an entry to the cache.
 *
 * Arguments:
 * - The ID
 * - The next filenumber we should cache
 */
void
idcache_add(const char *id, int next_filenum)
{
	struct id_record *existing, *idr;

	if ((idr = malloc(sizeof(*idr))) == NULL)
		return;
	if ((idr->id = strdup(id)) == NULL) {
		free(idr);
		return;
	}

	idr->last_used = time(NULL);
	idr->next_filenum = next_filenum;

	/*
	 * Add to the red/black tree. In theory, there should not be
	 * an existing entry. Check for this.
	 */
	existing = RB_INSERT(id_tree, &id_tree_head[tdidx], idr);
	assert(existing == NULL);
	if (existing != NULL) {
		existing->next_filenum = next_filenum;
		free(idr->id);
		free(idr);
		return;
	}
	TAILQ_INSERT_TAIL(&expiryq_head[tdidx], idr, tq);
}

/*
 * Get an entry from the cache.
 *
 * Arguments:
 * - The ID
 *
 * Return Value:
 * If a matching entry is found, a pointer to its next_filenum field.
 * Otherwise, NULL.
 */
int *
idcache_get(const char *id)
{
	struct id_record *idr;

	/* Find a matching record. */
	idr = RB_FIND(id_tree, &id_tree_head[tdidx],
	    __DECONST(struct id_record *, &id));

	/* If we found a matching record, reset its expiry. */
	if (idr != NULL) {
		idr->last_used = time(NULL);
		TAILQ_REMOVE(&expiryq_head[tdidx], idr, tq);
		TAILQ_INSERT_TAIL(&expiryq_head[tdidx], idr, tq);
	}

	return (idr == NULL ? (int *)NULL : &idr->next_filenum);
}
