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

#ifndef LIBCOMMON_H
#define LIBCOMMON_H

#include "types.h"
#include "alloc-inl.h"
// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

typedef struct afl_sharedmem {

#ifdef USEMMAP
  int  g_shm_id;
  char g_shm_file_path[20];
#else
  int shm_id;
#endif

  u8 *   map;
  size_t map_size;

} afl_sharedmem_t;

// Functions to create Shared memory region, for feedback and opening inputs and
// stuff.
u8 * afl_sharedmem_init(afl_sharedmem_t *, size_t);
void afl_sharedmem_deinit(afl_sharedmem_t *);

// We're declaring a few structs here which have an interdependency between them

typedef struct fuzz_one fuzz_one_t;

typedef struct engine engine_t;

typedef struct stage stage_t;

typedef struct executor executor_t;

typedef struct mutator mutator_t;

void * insert_substring(void *buf, size_t len, void *token, size_t token_len,
                        size_t offset);
int    rand_below(size_t limit);
size_t erase_bytes(void *buf, size_t len, size_t offset, size_t remove_len);
void * insert_bytes(void *buf, size_t len, u8 byte, size_t insert_len,
                    size_t offset);

#endif

