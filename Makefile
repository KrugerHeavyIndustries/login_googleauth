#	$Id: Makefile,v 1.1.1.1 2012/03/16 14:13:08 raxis Exp $

PROG=	login_googleauth
MAN=	login_googleauth.8
SRCS=	login_googleauth.c login_passwd.c pwd_gensalt.c googleauth.c \
	base32.c 
CFLAGS+=-DPASSWD -Wall -Wbounded -std=c99 -ggdb -O0 -I/usr/src/libexec/login_passwd
	
DPADD+= ${LIBUTIL}
LDADD+= -lutil -lcrypto
.PATH: /usr/src/libexec/login_passwd /usr/src/usr.bin/passwd

BINOWN=	root
BINGRP=	auth
BINMODE=2555
BINDIR=	/usr/libexec/auth

.include <bsd.prog.mk>
