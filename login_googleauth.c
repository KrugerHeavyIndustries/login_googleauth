/*
 * bsd_auth login program supporting Google's two-factor authentication 
 *
 * Copyright (c) 2012 Chris Kruger <chris@krugerheavyindustries.com>
 * Portions Copyright (c) 2010 Daniel Hartmeier <daniel@benzedrine.cx>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <ctype.h>
#include <login_cap.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "common.h"
#include "googleauth.h"

#define	MODE_LOGIN	0
#define	MODE_CHALLENGE	1
#define	MODE_RESPONSE	2

#define	AUTH_OK		0
#define	AUTH_FAILED	-1

FILE *back = NULL;

#define DBPATH "/var/db/googleauth";

static int seperate_code_and_password(char *code, char *password, 
                                      const char *unified);

static int clean_string(const char *);
static int googleauth_login(const char *, const char *);

int main(int argc, char *argv[])
{
	int ch, ret, mode = MODE_LOGIN;

	char *username;
   char code[_PASSWORD_LEN];
   char password[1024];
	char response[1024];
   char *unified = NULL;
   char *wheel = NULL;
   char *class = NULL;

   int lastchance = 0;

   memset(password, 0, sizeof(password));
   memset(response, 0, sizeof(response));

	setpriority(PRIO_PROCESS, 0, 0);

	openlog(NULL, LOG_ODELAY, LOG_AUTH);

	while ((ch = getopt(argc, argv, "dv:s:")) != -1) {
		switch (ch) {
		case 'd':
			back = stdout;
			break;
		case 'v':
			syslog(LOG_INFO, "-v %s", optarg);
			break;
		case 's':
			if (!strcmp(optarg, "login"))
				mode = MODE_LOGIN;
			else if (!strcmp(optarg, "response"))
				mode = MODE_RESPONSE;
			else if (!strcmp(optarg, "challenge"))
				mode = MODE_CHALLENGE;
			else {
				syslog(LOG_ERR, "%s: invalid service", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			syslog(LOG_ERR, "usage error1");
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 && argc != 1) {
		syslog(LOG_ERR, "usage error2");
		exit(EXIT_FAILURE);
	}
	username = argv[0];
	/* passed by sshd(8) for non-existing users */
	if (!strcmp(username, "NOUSER"))
		exit(EXIT_FAILURE);
	if (!clean_string(username)) {
		syslog(LOG_ERR, "clean_string username");
		exit(EXIT_FAILURE);
	}

	if (back == NULL && (back = fdopen(3, "r+")) == NULL) {
		syslog(LOG_ERR, "user %s: fdopen: %m", username);
		exit(EXIT_FAILURE);
	}

	switch (mode) {
		case MODE_LOGIN:
			if ((unified = getpass("Password:")) == NULL) {
				syslog(LOG_ERR, "user %s: getpass (Password)",
				    username);
				exit(EXIT_FAILURE);
			}
#if 0
         if ((password = getpass("Verification Code:")) == NULL) { 
            syslog(LOG_ERR, "user %s: getpass (Verification Code): %m",
                  username);
            exit(EXIT_FAILURE);
         }
         strncpy(code, password, _PASSWORD_LEN);
			if ((password = getpass("Password:")) == NULL) {
				syslog(LOG_ERR, "user %s: getpass (Password): %m",
				    username);
				exit(EXIT_FAILURE);
			}
#endif 
			break;
		case MODE_CHALLENGE:
			/* see login.conf(5) section CHALLENGES */
			fprintf(back, "%s\n", BI_SILENT);
         //fprintf(back, BI_VALUE " challenge %s\n", "Verification Code:");
         //fprintf(back, BI_CHALLENGE "\n");
         //fprintf(back, BI_FDPASS "\n");
         //fflush(back);
			exit(EXIT_SUCCESS);
			break;
		case MODE_RESPONSE: {
			/* see login.conf(5) section RESPONSES */
			/* this happens e.g. when called from sshd(8) */
			int count;
			mode = 0;
			count = -1;
			while (++count < sizeof(response) &&
			    read(fileno(back), &response[count], (size_t)1) ==
			    (ssize_t)1) {
				if (response[count] == '\0' && ++mode == 2)
					break;
				if (response[count] == '\0' && mode == 1) {
					unified = response + count + 1;
				}
			}
#if 0
         syslog(LOG_ERR, "got %s", unified);
#endif

			if (mode < 2) {
				syslog(LOG_ERR, "user %s: protocol error "
				    "on back channel", username);
				exit(EXIT_FAILURE);
			}
			break;
		}
	}

   if (seperate_code_and_password(code, password, unified)) {
      syslog(LOG_ERR, "user %s: incorrect format", username);
      exit(EXIT_FAILURE);
   }

	ret = googleauth_login(username, code); 

//   if (ret == AUTH_OK) 
//      ret = pwd_login(username, password, wheel, lastchance, class);

   memset(password, 0, sizeof(password));
   memset(response, 0, sizeof(response));
	if (unified != NULL){
      memset(unified, 0, strlen(unified));
	}
   if (ret != AUTH_OK) {
		syslog(LOG_INFO, "user %s: reject", username);
		fprintf(back, BI_REJECT "\n");
	}
	else { 
      syslog(LOG_INFO, "user %s: accepted", username);
		//This print statement returns the 'BI_AUTH' signal back to the bsd_auth
		//subsystem to proove the user account authenticated correctly. 
		//By putting this here, and commenting out the 'ret=pwd_login' statement
		//above, we shortcircuit the check to /etc/master.passwd for a user password
		//and rely ONLY on the GoogleAuth token for authentication. 
		fprintf(back, BI_AUTH "\n");
   }
	closelog();
	exit(EXIT_SUCCESS);
}

static int
seperate_code_and_password(char *code, char *password, const char *unified) 
{     
   // Verification are six digits starting with '0'..'9',
   // scratch codes are eight digits starting with '1'..'9'
   //
   // OpenBSD provides strlcpy, which is a more robust string copy
   // method. This code has been migrated to the strlcpy method
   // from the strncpy method because strncpy was producing 
   // corrupt tokenization for code lengths larger than 7.
   size_t len = strlen(unified);
   size_t span = strspn(unified, "0123456789");
   switch (span) {
      case 6:
         strlcpy(code, unified, 7);
         strlcpy(password, unified + 6, len - 5);
         return 0;
      case 8:
         strlcpy(code, unified, 9);
         strlcpy(password, unified + 8, len - 7);
         return 0;
   }
   return 1;
}

static int
clean_string(const char *s)
{
	while (*s) {
		if (!isalnum(*s) && *s != '-' && *s != '_')
			return (0);
		++s;
	}
	return (1);
}

static int
googleauth_login(const char *username, const char *password)
{
   uint8_t *secret = NULL;
   int      secretLen = 0;
   int      code = 0;
   char     *endptr;
   Config   config;

   if (read_cfg(username, &config)) {
		syslog(LOG_INFO, "user %s: error in user conf file", username);
      exit(EXIT_FAILURE);
   }

   long l = strtol(password, &endptr, 10);
   if (l < 0 || *endptr) {
      syslog(LOG_ERR, "user %s: failed to extract verification code", 
            username);
      return (AUTH_FAILED);
   }

   code = (int)l;

   if ((secret = get_shared_secret(username, &secretLen))) {
      int advance = 0;
      if (check_scratch_codes(username, code)) {
         if (config.is_totp) { 
            if (check_timebased_code(&config, secret, secretLen, code)) { 
#if 0 
               syslog(LOG_ERR, "user %s code %d: " 
                     "check_timebased_code != 0", 
                        username,
                        code); 
#else
               syslog(LOG_ERR, "user %s: " 
                     "check_timebased_code != 0", 
                        username);
#endif
               if (secret) {
                  memset(secret, 0, secretLen);
                  free(secret);
               }
               return (AUTH_FAILED);
            }
         } else { 
            int hotp_counter = get_hotp_counter(username);
            if (check_counterbased_code(&config, secret, secretLen, code,
                                        hotp_counter, &advance)) {
               syslog(LOG_ERR, "user %s: check_counterbased_code != 0",
                        username);
               if (secret) {
                  memset(secret, 0, secretLen);
                  free(secret);
               }
               return (AUTH_FAILED);
            }

            // If an hotp login attempt has been made, 
            // the counter must always be advanced by at least one
            if (advance) {
               if (advance_counter_by(username, hotp_counter, advance)) {
                  syslog(LOG_ERR, "user %s: failed to advance hotp counter",
                        username);
                  if (secret) { 
                     memset(secret, 0, secretLen);
                     free(secret);
                  }
                  return (AUTH_FAILED);
               }
            }
         }  
      }

      if (secret) {
         memset(secret, 0, secretLen);
         free(secret);
      }

      return (AUTH_OK);
   }

   return (AUTH_FAILED);
}
