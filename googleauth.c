// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "base32.h"
#include "googleauth.h"

#define DBPATH "/var/db/googleauth"
#define COUNTER_STRING_LENGTH 40

static char* get_db_filename(char *fn, int size, const char *username,
                             const char *ext) {
   snprintf(fn, size, "%s/%s.%s", DBPATH, username, ext);
   return fn;
}

static int open_db_file(const char *username, const char *ext) {
   int fd; 
   char fn[MAXPATHLEN];
   get_db_filename(fn, sizeof(fn), username, ext);
   if ((fd = open(fn, O_RDONLY)) == 0) {
		syslog(LOG_ERR, "user %s: fopen: %s: %m", username, fn);
      return 0;
   }
   return fd;
}

static char* read_db_file(int fd) { 

   struct stat sb;
   if (fstat(fd, &sb) < 0) {
      return NULL; 
   }

   //if ((sb.st_mode & 03577) != 0400 || !S_ISREG(sb.st_mode)) {
      
      //sb.st_uid != (uid_t)uid) {
    // char buf[80];
    //if (params->fixed_uid) {
    //  sprintf(buf, "user id %d", params->uid);
    //  username = buf;
    //}
    // FIXME log_message(LOG_ERR, pamh,
            //    "Secret file \"%s\" must only be accessible by %s",
            //    secret_filename, username);
   //   return NULL;            
   //}

   // Sanity check for file length
   if (sb.st_size < 1 || sb.st_size > 64*1024) {
      syslog(LOG_ERR, "invalid file size for fd = %d", fd);
      return NULL;
   }
   
   char *buf = malloc(sb.st_size + 1);
   if (!buf || read(fd, buf, sb.st_size) != sb.st_size) {
      syslog(LOG_ERR, "Could not read file");
      free(buf);
      return NULL;
   }

   // Terminate the buffer with a NUL byte.
   buf[sb.st_size] = '\0';

   return buf;
}

uint8_t *get_shared_secret(const char *username, int *secretLen) {

   int fd; 
   if ((fd = open_db_file(username, "secret")) == 0) {
      return NULL;
   }

   char *buf = read_db_file(fd); 
   close(fd);
   if (buf == NULL) { 
      return NULL;
   }
   fd = -1;

   // Decode secret key
   int base32Len = strcspn(buf, "\n");
   *secretLen = (base32Len * 5 + 7)/8;
   uint8_t *secret = malloc(base32Len + 1);
   if (secret == NULL) {
      syslog(LOG_ERR, "malloc() failed");
      *secretLen = 0;
      free(buf);
      return NULL;
   }
   memcpy(secret, buf, base32Len);
   secret[base32Len] = '\0';
   if ((*secretLen = base32_decode(secret, secret, base32Len)) < 1) {
      syslog(LOG_ERR, "Could not find a valid BASE32 encoded secret " \
             "in totp file");
      memset(secret, 0, base32Len);
      free(secret);
      free(buf);
      return NULL;
   }
   memset(secret + *secretLen, 0, base32Len + 1 - *secretLen);
   free(buf);
   return secret;
}

#ifdef TESTING
static time_t current_time;
void set_time(time_t t) __attribute__((visibility("default")));
void set_time(time_t t) {
  current_time = t;
}

static time_t get_time(void) {
  return current_time;
}
#else
static time_t get_time(void) {
  return time(NULL);
}
#endif

static int get_timestamp(void) {
  return get_time()/30;
}

long get_hotp_counter(const char *username) {

   int fd;
   if ((fd = open_db_file(username, "counter")) == 0) {
      return -1;
   }
   char *buf = read_db_file(fd);
   long counter = 0;
   if (buf != NULL) {
      counter = strtol(buf, NULL, 10);
      free(buf);
   }
   close(fd);
   return counter;
}

/* Checks for possible use of scratch codes. Returns -1 on error, 
 * 0 on success, and 1, if no scratch code had been entered, 
 * and subsequent tests should be applied.
 */
int check_scratch_codes(const char *username, int code) {
   
   int fd;
   char *buf;
   char *ptr;

   if ((fd = open_db_file(username, "scratch")) == 0) {
      return 1;
   }

   buf = read_db_file(fd);
   close(fd);
   if (buf == NULL) { 
      return 1;
   }

   ptr = buf;

   // Check if this is one of the scratch codes
   char *endptr = NULL;
   for (;;) {
      // Skip newlines and blank lines
      while (*ptr == '\r' || *ptr == '\n') {
         ptr++;
      }

      // Try to interpret the line as a scratch code
      errno = 0;
      int scratchcode = (int)strtoul(ptr, &endptr, 10);

      // Sanity check that we read a valid scratch code. Scratchcodes 
      // are all numeric eight-digit codes. There must not be any other 
      // information on that line
      if (errno ||
         ptr == endptr ||
         (*endptr != '\r' && *endptr != '\n' && *endptr) ||
         scratchcode <  10*1000*1000 ||
         scratchcode >= 100*1000*1000) {
         break;
      }

      // Check if the code matches
      if (scratchcode == code) {
         // Remove scratch code after using it
         while (*endptr == '\n' || *endptr == '\r') {
            ++endptr;
         }
         memmove(ptr, endptr, strlen(endptr) + 1);
         memset(strrchr(ptr, '\000'), 0, endptr - ptr + 1);

         char fn[MAXPATHLEN];
         char temp_fn[MAXPATHLEN];

         get_db_filename(fn, sizeof(fn), username, "scratch");
         get_db_filename(temp_fn, sizeof(temp_fn), username, "scratch~");

         int fd = open(temp_fn, 
            O_WRONLY|O_CREAT|O_NOFOLLOW|O_TRUNC|O_EXCL, 0440);

         size_t w = write(fd, buf, strlen(buf));
         if (w != (size_t)strlen(buf) || 
                        rename(temp_fn, fn) != 0) {
            unlink(temp_fn);
         }
         free(buf);
         close(fd);
         
         return 0;
      }
      ptr = endptr;
   }

   free(buf);

   // No scratch code has been used. Continue checking other types 
   // of codes.
   return 1;
}

int compute_code(const uint8_t *secret, int secretLen, unsigned long value) {
  uint8_t val[8];
  for (int i = 8; i--; value >>= 8) {
    val[i] = value;
  }
  int sha1_digest_length; 
  uint8_t hash[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha1(), secret, secretLen, val, 8, hash, &sha1_digest_length);
  memset(val, 0, sizeof(val));
  int offset = hash[sha1_digest_length - 1] & 0xF;
  unsigned int truncatedHash = 0;
  for (int i = 0; i < 4; ++i) {
    truncatedHash <<= 8;
    truncatedHash  |= hash[offset + i];
  }
  memset(hash, 0, sizeof(hash));
  truncatedHash &= 0x7FFFFFFF;
  truncatedHash %= 1000000;
  return truncatedHash;
}

/* If a user repeated attempts to log in with the same time skew, remember
 * this skew factor for future login attempts.
 */

static int check_time_skew(int skew, int tm) {
                           
  //int rc = -1;

  // Parse current RESETTING_TIME_SKEW line, if any.
  //char *resetting = get_cfg_value("RESETTING_TIME_SKEW", *buf);
  //if (resetting == &oom) {
    // Out of memory. This is a fatal error.
   // return -1;
 // }

  // If the user can produce a sequence of three consecutive codes that fall
  // within a day of the current time. And if he can enter these codes in
  // quick succession, then we allow the time skew to be reset.
  // N.B. the number "3" was picked so that it would not trigger the rate
  // limiting limit if set up with default parameters.
//  unsigned int tms[3];
//  int skews[sizeof(tms)/sizeof(int)];
//
//  int num_entries = 0;
//  if (resetting) {
//    char *ptr = resetting;
//
//    // Read the three most recent pairs of time stamps and skew values into
//    // our arrays.
//    while (*ptr && *ptr != '\r' && *ptr != '\n') {
//      char *endptr;
//      errno = 0;
//      unsigned int i = (int)strtoul(ptr, &endptr, 10);
//      if (errno || ptr == endptr || (*endptr != '+' && *endptr != '-')) {
//        break;
//      }
//      ptr = endptr;
//      int j = (int)strtoul(ptr + 1, &endptr, 10);
//      if (errno ||
//          ptr == endptr ||
//          (*endptr != ' ' && *endptr != '\t' &&
//           *endptr != '\r' && *endptr != '\n' && *endptr)) {
//        break;
//      }
//      if (*ptr == '-') {
//        j = -j;
//      }
//      if (num_entries == sizeof(tms)/sizeof(int)) {
//        memmove(tms, tms+1, sizeof(tms)-sizeof(int));
//        memmove(skews, skews+1, sizeof(skews)-sizeof(int));
//      } else {
//        ++num_entries;
//      }
//      tms[num_entries-1]   = i;
//      skews[num_entries-1] = j;
//      ptr = endptr;
//    }
//
//    // If the user entered an identical code, assume they are just getting
//    // desperate. This doesn't actually provide us with any useful data,
//    // though. Don't change any state and hope the user keeps trying a few
//    // more times.
//    if (num_entries &&
//        tm + skew == tms[num_entries-1] + skews[num_entries-1]) {
//      free((void *)resetting);
//      return -1;
//    }
//  }
//  free((void *)resetting);
//
//  // Append new timestamp entry
//  if (num_entries == sizeof(tms)/sizeof(int)) {
//    memmove(tms, tms+1, sizeof(tms)-sizeof(int));
//    memmove(skews, skews+1, sizeof(skews)-sizeof(int));
//  } else {
//    ++num_entries;
//  }
//  tms[num_entries-1]   = tm;
//  skews[num_entries-1] = skew;
//
//  // Check if we have the required amount of valid entries.
//  if (num_entries == sizeof(tms)/sizeof(int)) {
//    unsigned int last_tm = tms[0];
//    int last_skew = skews[0];
//    int avg_skew = last_skew;
//    for (int i = 1; i < sizeof(tms)/sizeof(int); ++i) {
//      // Check that we have a consecutive sequence of timestamps with no big
//      // gaps in between. Also check that the time skew stays constant. Allow
//      // a minor amount of fuzziness on all parameters.
//      if (tms[i] <= last_tm || tms[i] > last_tm+2 ||
//          last_skew - skew < -1 || last_skew - skew > 1) {
//        goto keep_trying;
//      }
//      last_tm   = tms[i];
//      last_skew = skews[i];
//      avg_skew += last_skew;
//    }
//    avg_skew /= (int)(sizeof(tms)/sizeof(int));
//
//    // The user entered the required number of valid codes in quick
//    // succession. Establish a new valid time skew for all future login
//    // attempts.
//    char time_skew[40];
//    sprintf(time_skew, "%d", avg_skew);
//    if (set_cfg_value("TIME_SKEW", time_skew, buf) < 0) {
//      return -1;
//    }
//    rc = 0;
//  keep_trying:;
//  }
//
//  // Set the new RESETTING_TIME_SKEW line, while the user is still trying
//  // to reset the time skew.
//  char reset[80 * (sizeof(tms)/sizeof(int))];
//  *reset = '\000';
//  if (rc) {
//    for (int i = 0; i < num_entries; ++i) {
//      sprintf(strrchr(reset, '\000'), " %d%+d" + !*reset, tms[i], skews[i]);
//    }
//  }
//  if (set_cfg_value("RESETTING_TIME_SKEW", reset, buf) < 0) {
//    return -1;
//  }
//
//  // Mark the state file as changed
//  //*updated = 1;
//
//  return rc;
   return 0;
}


/* Checks for time based verification code. Returns -1 on error, 
 * 0 on success, and 1, if no time based code had been entered, 
 * and subsequent tests should be applied.
 */
int check_timebased_code(struct Config *config, const uint8_t *secret,
                         int length, int code) {
  if (code < 0 || code >= 1000000) {
    // All time based verification codes are no longer than six digits.
    return 1;
  }

  // Compute verification codes and compare them with user input
  const int tm = get_timestamp();
  //const char *skew_str = get_cfg_value("TIME_SKEW", *buf);
  //if (skew_str == &oom) {
    // Out of memory. This is a fatal error
    //return -1;
  //}

  int skew = 0;
  //if (skew_str) {
  //  skew = (int)strtol(skew_str, NULL, 10);
  //}
  //free((void *)skew_str);

  int window = config->window_size;
  if (window == 0) {
    return -1;
  }
  for (int i = -((window-1)/2); i <= window/2; ++i) {
    unsigned int hash = compute_code(secret, length, tm + skew + i);
    if (hash == (unsigned int)code) {
      return 0;
    }
  }

  if (1 /* FIXME want skew check yeah? !params->noskewadj */) {
    // The most common failure mode is for the clocks to be insufficiently
    // synchronized. We can detect this and store a skew value for future
    // use.
    skew = 1000000;
    for (int i = 0; i < 25*60; ++i) {
      unsigned int hash = compute_code(secret, length, tm - i);
      if (hash == (unsigned int)code && skew == 1000000) {
        // Don't short-circuit out of the loop as the obvious difference in
        // computation time could be a signal that is valuable to an attacker.
        skew = -i;
      }
      hash = compute_code(secret, length, tm + i);
      if (hash == (unsigned int)code && skew == 1000000) {
        skew = i;
      }
    }
    if (skew != 1000000) {
      return check_time_skew(skew, tm);
    }
  }

  return 1;
}


/* Checks for counter based verification code. Returns -1 on error, 0 on
 * success, and 1, if no counter based code had been entered, 
 * and subsequent
 * tests should be applied.
 */
int check_counterbased_code(struct Config *config,
                            const uint8_t*secret,
                            int length, int code,
                            long hotp_counter,
                            int *must_advance_counter) {
  if (hotp_counter < 1) {
    // The secret file did not actually contain information for a 
    // counter-based code. Return to call and see if any auth methods
    // apply.
    return 1;
  }

  if (code < 0 || code >= 1000000) {
    // All counter based verification codes are no longer than six digits.
    return 1;
  }

  // Compute [window_size] verification codes and compare them with 
  // user input. Future codes are allowed in case the user computed 
  // but did not use a code.
  int window = config->window_size;
  if (!window) {
    return -1;
  }
  for (int i = 0; i < window; ++i) {
    unsigned int hash = compute_code(secret, length, hotp_counter + i);
    if (hash == (unsigned int)code) {
      *must_advance_counter = i + 1;
      return 0;
    }
  }
  *must_advance_counter = 1;
  return 1;
}

int read_cfg(const char* username, struct Config* config) {
   char* buf; 
   char* ptr;
   char* field;
   const int expected = 7;
   int fd; 
   int i;
   if ((fd = open_db_file(username, "conf")) == 0) {
      return 1;
   }
   buf = read_db_file(fd);
   close(fd);
   if (buf == NULL) {
      return 1;
   }
   ptr = buf;
   for (i = 0; i < expected && 
         ((field = strsep(&ptr, " \t")) != NULL); i++)  {
      switch(i) {
         case 0:
            config->is_totp = strncmp("HOTP_AUTH", field, 9);
            break;
         case 1:
            config->disallow_reuse = strncmp("ALLOW_REUSE", field, 11);
            break;
         case 2:
            // WINDOW_SIZE 
            break;
         case 3:
            config->window_size = strtol(field, NULL, 10);
            break;
         case 4:
            // RATE_LIMIT
            break;
         case 5:
            config->rate_limit.attempts = strtol(field, NULL, 10); 
            break;
         case 6:
            config->rate_limit.window = strtol(field, NULL, 10);
            break;
      };
   }
   free(buf);
   if (i != expected) { 
      fprintf(stderr, "%s.conf: unexpected format\n", username);
      return 1;
   }
   return 0;
}

int advance_counter_by(const char *username, long hotp_counter, 
                       int advance) {
   
   char counter_str[COUNTER_STRING_LENGTH];
   char counter_fn[MAXPATHLEN];
   char temp_fn[MAXPATHLEN];

   int ok = 0;

   get_db_filename(counter_fn, sizeof(counter_fn), username, "counter");
   get_db_filename(temp_fn, sizeof(temp_fn), username, "counter~");

   int fd = open(temp_fn, 
         O_WRONLY|O_CREAT|O_NOFOLLOW|O_TRUNC|O_EXCL, 0440);

   snprintf(counter_str, COUNTER_STRING_LENGTH, "%ld", 
         hotp_counter + advance);

   size_t w = write(fd, counter_str, strlen(counter_str));
   if (w != (size_t)strlen(counter_str) || 
                        rename(temp_fn, counter_fn) != 0) {
      unlink(temp_fn);
      ok = 1;
   }
   close(fd);
   return ok;
}

int advance_counter(const char *username, int hotp_counter) {
   return advance_counter_by(username, hotp_counter, 1);
}
