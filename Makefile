#------------------------------------------------------------------------------

SOURCE= login_googleauth.c googleauth.c /usr/src/src/usr.bin/passwd/pwd_gensalt.c base32.c /usr/src/libexec/login_passwd/login_passwd.c
KRB5_PASSWD_SOURCE = krb5.c
KRB5_SOURCE = /usr/src/libexec/login_krb5/login_krb5.c
PROGRAM=login_googleauth
INCLUDES=/usr/src/libexec/login_passwd
CFLAGS+=-Wall -Wbounded -std=c99 -ggdb -O0
LIBRARIES=util -lcrypto
KRB5_LIBRARIES=krb5 -lasn1 -lcrypto -lutil
CC=gcc

#------------------------------------------------------------------------------

.PHONY: password

password : $(SOURCE)

	$(CC) -DPASSWD $(CFLAGS) -I$(INCLUDES) $(SOURCE) -o$(PROGRAM) -l$(LIBRARIES)

.PHONY: krb5_password

krb5_password : $(SOURCE) $(KRB5_SOURCE)

	$(CC) -DKRB5_PASSWD $(CFLAGS) -I$(INCLUDES) $(SOURCE) $(KRB5_PASSWD_SOURCE) -o$(PROGRAM) -l$(KRB5_LIBRARIES) -l$(LIBRARIES)

.PHONY: krb5

krb5 : $(SOURCE)

	$(CC) -DKRB5 $(CFLAGS) -I$(INCLUDES) $(SOURCE) $(KRB5_SOURCE)  -o$(PROGRAM) -l$(KRB5_LIBRARIES) -l$(LIBRARIES)

