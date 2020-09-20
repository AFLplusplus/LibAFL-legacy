/*
   american fuzzy lop++ - fuzzer header
   ------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */

/* This file contains commonly used functionality for libafl */

#ifndef COMMON_H
#define COMMON_H

#include <pthread.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>

#include "types.h"
#include "alloc-inl.h"
#include "afl-returns.h"

#define AFL_DEINITIALIZED (0xAF1DA10C)

// We're declaring a few structs here which have an interdependency between them

typedef struct afl_fuzz_one afl_fuzz_one_t;

typedef struct afl_engine afl_engine_t;

typedef struct afl_stage afl_stage_t;

typedef struct afl_executor afl_executor_t;

typedef struct afl_mutator afl_mutator_t;

// Returns new buf containing the substring token
void *afl_insert_substring(u8 *buf, size_t len, void *token, size_t token_len, size_t offset);
// Erases remove_len number of bytes from offset
size_t afl_erase_bytes(u8 *buf, size_t len, size_t offset, size_t remove_len);

// Inserts a certain length of a byte value (byte) at offset in buf
u8 *afl_insert_bytes(u8 *buf, size_t len, u8 byte, size_t insert_len, size_t offset);

static inline char **afl_argv_cpy_dup(int argc, char **argv) {

  int i = 0;

  char **ret = calloc(1, (argc + 1) * sizeof(char *));
  if (!ret) { return NULL; }

  for (i = 0; i < argc; i++) {

    ret[i] = strdup(argv[i]);
    if (!ret[i]) {

      int k;
      for (k = 0; k < i; k++) {

        free(ret[k]);

      }

      free(ret);
      return NULL;

    }

  }

  ret[i] = NULL;

  return ret;

}

/* Get unix time in microseconds */
u64 afl_get_cur_time_us(void);

/* Get unix time in microseconds */
u64 afl_get_cur_time(void);

/* Get unix time in seconds */
u64 afl_get_cur_time_s(void);

/* returns true, if the given dir exists, else false */
bool afl_dir_exists(char *dirpath);

/* This function uses select calls to wait on a child process for given
 * timeout_ms milliseconds and kills it if it doesn't terminate by that time */
static inline u32 afl_read_s32_timed(s32 fd, s32 *buf, u32 timeout_ms) {

  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  struct timeval timeout;
  int            sret;
  ssize_t        len_read;

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;
#if !defined(__linux__)
  u64 read_start = afl_get_cur_time_us();
#endif

  /* set exceptfds as well to return when a child exited/closed the pipe. */
restart_select:
  sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

  if (likely(sret > 0)) {

  restart_read:
    len_read = read(fd, (u8 *)buf, 4);

    if (likely(len_read == 4)) {  // for speed we put this first

#if defined(__linux__)
      u32 exec_ms = MIN(timeout_ms, ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
#else
      u32 exec_ms = MIN(timeout_ms, afl_get_cur_time_us() - read_start);
#endif

      // ensure to report 1 ms has passed (0 is an error)
      return exec_ms > 0 ? exec_ms : 1;

    } else if (unlikely(len_read == -1 && errno == EINTR)) {

      goto restart_read;

    } else if (unlikely(len_read < 4)) {

      return 0;

    }

  } else if (unlikely(!sret)) {

    *buf = -1;
    return timeout_ms + 1;

  } else if (unlikely(sret < 0)) {

    if (likely(errno == EINTR)) goto restart_select;

    *buf = -1;
    return 0;

  }

  return 0;  // not reached

}

#endif

