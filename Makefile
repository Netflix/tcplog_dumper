PROG=		tcplog_dumper
SRCS=		${PROG}.c \
		tcplog_idcache.c \
		tcplog_writev.c \
		tcplog_xz.c
WARNS?=		6
LDADD+=		-llzma -lthr
DEBUG_FLAGS=	-ggdb

.include <bsd.prog.mk>
