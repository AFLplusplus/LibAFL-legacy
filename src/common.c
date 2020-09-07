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

#include "common.h"

/* Get unix time in microseconds */
inline u64 afl_get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

/* Get unix time in seconds */
u64 afl_get_cur_time(void) {

  return afl_get_cur_time_us() / 1000;

}

/* Few helper functions */

void *afl_insert_substring(u8 *buf, size_t len, void *token, size_t token_len,
                           size_t offset) {

  void *new_buf = calloc(len + token_len + 1, 1);
  memmove(new_buf, buf, offset);

  memmove(new_buf + offset, token, token_len);

  memmove(new_buf + offset + token_len, buf + offset, len - offset);

  return new_buf;

}

/* This function inserts given number of bytes at a certain offset in a string
  and returns a ptr to the newly allocated memory. NOTE: You have to free the
  original memory(if malloced) yourself*/
u8 *afl_insert_bytes(u8 *buf, size_t len, u8 byte, size_t insert_len,
                     size_t offset) {

  u8 *new_buf = calloc(len + insert_len + 1, 1);

  memmove(new_buf, buf, offset);

  memset(new_buf + offset, byte, insert_len);

  memmove(new_buf + offset + insert_len, buf + offset, len - offset);

  return new_buf;

}

size_t afl_erase_bytes(u8 *buf, size_t len, size_t offset, size_t remove_len) {

  memmove(buf + offset, buf + offset + remove_len, len - offset - remove_len);
  memset(buf + len - remove_len, 0x0, remove_len);

  size_t new_size = len - remove_len;

  return new_size;

}

