/*
 * Written by Chris Kruger <chris.kruger@krugerheavyindustries.com>
 * Copyright (c) 2012 Chris Kruger <chris.kruger@krugerheavyindustries.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __GOOGLEAUTH_H__
#define __GOOGLEAUTH_H__

#include <stdint.h>
#include <string.h>

typedef struct RateLimit { 
   int   attempts;
   int   window;
} RateLimit;

typedef struct Config { 
   int      is_totp;
   int      disallow_reuse;
   int      window_size;
   RateLimit rate_limit;
} Config;

extern int google_authenticator(const char* username,
                                const char* password, int flags);

extern int read_cfg(const char* username, Config* config);

extern uint8_t *get_shared_secret(const char *username, int *secretLen);

extern long get_hotp_counter(const char *username);

extern int check_scratch_codes(const char *username, int code);

extern int check_timebased_code(struct Config *config, 
                                const uint8_t *secret,
                                int length, int code);

extern int check_counterbased_code(struct Config *config,
                                   const uint8_t *secret,
                                   int length, int code,
                                   long hotp_counter,
                                   int *advance);

extern int advance_counter_by(const char *username, 
                              long hotp_counter, 
                              int advance);

#endif
