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

#ifndef LIBAFL_UTILS_H
#define LIBAFL_UTILS_H

#include "types.h"
#include "alloc.h"

/*
  Returns new buf containing the substring token.
*/
void *afl_insert_substring(u8 *src_buf, u8 *dest_buf, size_t len, void *token, size_t token_len, size_t offset);

/*
  Erases remove_len number of bytes from offset.
*/
size_t afl_erase_bytes(u8 *buf, size_t len, size_t offset, size_t remove_len);

/*
  Inserts a certain length of a byte value (byte) at offset in buf.
*/
u8 *afl_insert_bytes(u8 *src_buf, u8 *dest_buf, size_t len, u8 byte, size_t insert_len, size_t offset);

/*
  Copy argv.
*/
static inline char **afl_argv_cpy_dup(int argc, char **argv) {

  u32 i = 0;

  char **ret = afl_alloc((argc + 1) * sizeof(char *));
  if (!ret) return NULL;

  for (i = 0; i < argc; i++) {

    ret[i] = afl_strdup(argv[i]);
    if (!ret[i]) {

      u32 k;
      for (k = 0; k < i; k++)
        afl_free(ret[k]);

      afl_free(ret);
      return NULL;

    }

  }

  ret[i] = NULL;

  return ret;

}

#endif
