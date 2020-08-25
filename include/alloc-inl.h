/*
   american fuzzy lop++ - error-checking, memory-zeroing alloc routines
   --------------------------------------------------------------------

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

   This allocator is not designed to resist malicious attackers (the canaries
   are small and predictable), but provides a robust and portable way to detect
   use-after-free, off-by-one writes, stale pointers, and so on.

 */

#ifndef _HAVE_ALLOC_INL_H
#define _HAVE_ALLOC_INL_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "debug.h"

/* Initial size used for ck_maybe_grow */
#define INITIAL_GROWTH_SIZE (64)

/* User-facing macro to sprintf() to a dynamically allocated buffer.
Returns NULL if alloc or snprintf fails. */
#define alloc_printf(_str...)                               \
  ({                                                        \
                                                            \
    char *_tmp = NULL;                                      \
    s32   _len = snprintf(NULL, 0, _str);                   \
    if (_len >= 0) {                                        \
                                                            \
      _tmp = malloc(_len + 1);                              \
      if (_tmp) { snprintf((char *)_tmp, _len + 1, _str); } \
                                                            \
    }                                                       \
    _tmp;                                                   \
                                                            \
  })

/* This function calculates the next power of 2 greater or equal its argument.
 @return The rounded up power of 2 (if no overflow) or 0 on overflow.
*/
static inline size_t next_pow2(size_t in) {

  if (in == 0 || in > (size_t)-1) {

    return 0;                  /* avoid undefined behaviour under-/overflow */

  }

  size_t out = in - 1;
  out |= out >> 1;
  out |= out >> 2;
  out |= out >> 4;
  out |= out >> 8;
  out |= out >> 16;
  return out + 1;

}

/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
struct afl_alloc_buf {

  /* The complete allocated size, including the header of len
   * AFL_ALLOC_SIZE_OFFSET */
  size_t complete_size;
  /* ptr to the first element of the actual buffer */
  u8 buf[0];

};

#define AFL_ALLOC_SIZE_OFFSET (offsetof(struct afl_alloc_buf, buf))

/* Returs the container element to this ptr */
static inline struct afl_alloc_buf *afl_alloc_bufptr(void *buf) {

  return (struct afl_alloc_buf *)((u8 *)buf - AFL_ALLOC_SIZE_OFFSET);

}

/* Gets the maximum size of the buf contents (ptr->complete_size -
 * AFL_ALLOC_SIZE_OFFSET) */
static inline size_t afl_alloc_bufsize(void *buf) {

  return afl_alloc_bufptr(buf)->complete_size - AFL_ALLOC_SIZE_OFFSET;

}

/* This function makes sure *size is > size_needed after call.
 It will realloc *buf otherwise.
 *size will grow exponentially as per:
 https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
 Will return NULL and free *buf if size_needed is <1 or realloc failed.
 @return For convenience, this function returns *buf.
 */
static inline void *afl_realloc(void **buf, size_t size_needed) {

  struct afl_alloc_buf *new_buf = NULL;

  size_t current_size = 0;
  size_t next_size = 0;

  if (likely(*buf)) {

    /* the size is always stored at buf - 1*size_t */
    new_buf = afl_alloc_bufptr(*buf);
    current_size = new_buf->complete_size;

  }

  size_needed += AFL_ALLOC_SIZE_OFFSET;

  /* No need to realloc */
  if (likely(current_size >= size_needed)) { return *buf; }

  /* No initial size was set */
  if (size_needed < INITIAL_GROWTH_SIZE) {

    next_size = INITIAL_GROWTH_SIZE;

  } else {

    /* grow exponentially */
    next_size = next_pow2(size_needed);

    /* handle overflow: fall back to the original size_needed */
    if (unlikely(!next_size)) { next_size = size_needed; }

  }

  /* alloc */
  new_buf = realloc(new_buf, next_size);
  if (unlikely(!new_buf)) {

    *buf = NULL;
    return NULL;

  }

  new_buf->complete_size = next_size;
  *buf = (void *)(new_buf->buf);
  return *buf;

}

static inline void afl_free(void *buf) {

  if (buf) { free(afl_alloc_bufptr(buf)); }

}

/* Swaps buf1 ptr and buf2 ptr, as well as their sizes */
static inline void afl_swap_bufs(void **buf1, void **buf2) {

  void *scratch_buf = *buf1;
  *buf1 = *buf2;
  *buf2 = scratch_buf;

}

#undef INITIAL_GROWTH_SIZE

#endif                                               /* ! _HAVE_ALLOC_INL_H */
