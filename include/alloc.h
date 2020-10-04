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

/* this file contains anything allocator-realted libafl */

#ifndef LIBAFL_ALLOC_H
#define LIBAFL_ALLOC_H

#include "types.h"

#include "platform/print.h"
#include "platform/alloc.h"
#include "platform/string.h"

/* Initial size used for afl_realloc */
#define INITIAL_GROWTH_SIZE (64)

/* Macro to enforce allocation limits as a last-resort defense against
   integer overflows. */

#define ALLOC_CHECK_SIZE(_s)                                          \
  do {                                                                \
                                                                      \
    if ((_s) > MAX_ALLOC) ABORT("Bad alloc request: %u bytes", (_s)); \
                                                                      \
  } while (0)

/* Macro to check malloc() failures and the like. */

#define ALLOC_CHECK_RESULT(_r, _s)                                    \
  do {                                                                \
                                                                      \
    if (!(_r)) ABORT("Out of memory: can't allocate %u bytes", (_s)); \
                                                                      \
  } while (0)

/* Allocate a buffer, explicitly not zeroing it. Returns NULL for zero-sized
   requests. */

static inline void *afl_alloc_nozero(u32 size) {

  void *ret;

  if (!size) { return NULL; }

  ALLOC_CHECK_SIZE(size);
  ret = afl_platform_malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return (void *)ret;

}

/* Allocate a buffer, returning zeroed memory. */

static inline void *afl_alloc(u32 size) {

  void *mem;

  if (!size) { return NULL; }
  mem = afl_alloc_nozero(size);

  return memset(mem, 0, size);

}

/* Free memory. */

static inline void afl_free(void *mem) {

  if (!mem) { return; }

  alf_platform_free(mem);

}

/* Re-allocate a buffer, checking for issues and zeroing any newly-added tail.
   With DEBUG, the buffer is always reallocated to a new addresses and the
   old memory is clobbered with 0xFF. */

static inline void *afl_realloc(void *orig, u32 size) {

  void *ret;

  if (!size) {

    afl_free(orig);
    return NULL;

  }

  ALLOC_CHECK_SIZE(size);

  /* Catch pointer issues sooner: force relocation and make sure that the
     original buffer is wiped. */

  ret = afl_platform_realloc(orig, size);

  ALLOC_CHECK_RESULT(ret, size);

  return (void *)ret;

}

/* Create a buffer with a copy of a string. Returns NULL for NULL inputs. */

static inline u8 *afl_strdup(u8 *str) {

  u8 *ret;
  u32 size;

  if (!str) { return NULL; }

  size = strlen((char *)str) + 1;

  ALLOC_CHECK_SIZE(size);
  ret = (u8 *)afl_platform_malloc(size);
  ALLOC_CHECK_RESULT(ret, size);

  return (u8 *)memcpy(ret, str, size);

}

/* User-facing macro to sprintf() to a dynamically allocated buffer. */

#define afl_alloc_printf(_str...)                    \
  ({                                                 \
                                                     \
    u8 *_tmp;                                        \
    s32 _len = snprintf(NULL, 0, _str);              \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1);                       \
    snprintf((char *)_tmp, _len + 1, _str);          \
    _tmp;                                            \
                                                     \
  })

/* This function calculates the next power of 2 greater or equal its argument.
 @return The rounded up power of 2 (if no overflow) or 0 on overflow.
*/
static inline size_t next_pow2(size_t in) {

  // Commented this out as this behavior doesn't change, according to unittests
  // if (in == 0 || in > (size_t)-1) {

  //
  //   return 0;                  /* avoid undefined behaviour under-/overflow
  //   */
  //
  // }

  size_t out = in - 1;
  out |= out >> 1;
  out |= out >> 2;
  out |= out >> 4;
  out |= out >> 8;
  out |= out >> 16;
  return out + 1;

}

#define AFL_GROW_MAGIC (0xAF1A110C)

/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
struct afl_grow_buf {

  /* The complete allocated size, including the header of len
   * AFL_ALLOC_SIZE_OFFSET */
  size_t complete_size;
  /* Make sure this is an alloc_buf */
  size_t magic;
  /* ptr to the first element of the actual buffer */
  u8 __attribute__((aligned(8))) buf[0];

};

#define AFL_ALLOC_SIZE_OFFSET (offsetof(struct afl_grow_buf, buf))

/* Returs the container element to this ptr */
static inline struct afl_grow_buf *afl_grow_bufptr(void *buf) {

  return (struct afl_grow_buf *)((u8 *)buf - AFL_ALLOC_SIZE_OFFSET);

}

/* Gets the maximum size of the buf contents (ptr->complete_size -
 * AFL_ALLOC_SIZE_OFFSET) */
static inline size_t afl_grow_bufsize(void *buf) {

  return afl_grow_bufptr(buf)->complete_size - AFL_ALLOC_SIZE_OFFSET;

}

/*
  This function makes sure *size is > size_needed after call.
  It will realloc *buf otherwise.
  *size will grow exponentially as per:
  https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
  Will return NULL and free *buf if size_needed is <1 or realloc failed.
  @return For convenience, this function returns *buf.
*/
static inline void *afl_grow_realloc(void *buf, size_t size_needed) {

  struct afl_grow_buf *new_buf = NULL;

  size_t current_size = 0;
  size_t next_size = 0;

  if (likely(buf)) {

    /* the size is always stored at buf - 1*size_t */
    new_buf = afl_grow_bufptr(buf);
    if (unlikely(new_buf->magic != AFL_GROW_MAGIC)) {

      FATAL(
          "Illegal, non-null pointer passed to afl_grow_realloc (buf 0x%p, magic 0x%x)", new_buf, (unsigned)new_buf->magic);

    }

    current_size = new_buf->complete_size;

  }

  size_needed += AFL_ALLOC_SIZE_OFFSET;

  /* No need to realloc */
  if (likely(current_size >= size_needed)) { return buf; }

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
  new_buf = afl_realloc(new_buf, next_size);
  if (unlikely(!new_buf)) { return NULL; }

  new_buf->complete_size = next_size;
  new_buf->magic = AFL_GROW_MAGIC;
  return new_buf->buf;

}

static inline void *afl_grow_alloc(u32 size) {

  return afl_grow_realloc(NULL, size);

}

static inline void afl_grow_free(void *buf) {

  if (buf) afl_free(afl_grow_bufptr(buf));

}

#undef INITIAL_GROWTH_SIZE

#endif                                                                                       /* ! _HAVE_ALLOC_INL_H */

