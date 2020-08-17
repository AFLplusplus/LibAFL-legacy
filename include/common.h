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

#include <pthread.h>

#include "types.h"
#include "alloc-inl.h"
#include "afl-returns.h"

#define MAX_WORKERS 256

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

// Functions to create Shared memory region, for observation channels and
// opening inputs and stuff.
u8 * afl_sharedmem_init(afl_sharedmem_t *sharedmem, size_t map_size);
void afl_sharedmem_deinit(afl_sharedmem_t *sharedmem);

// We're declaring a few structs here which have an interdependency between them

typedef struct fuzz_one fuzz_one_t;

typedef struct engine engine_t;

typedef struct stage stage_t;

typedef struct executor executor_t;

typedef struct mutator mutator_t;

/* A global array of all the registered engines */
pthread_mutex_t fuzz_worker_array_lock; 
engine_t *registered_fuzz_workers[MAX_WORKERS];
u64       fuzz_workers_count;

/* Function to register/add a fuzz worker (engine). To avoid race condition, add
 * mutex here(Won't be performance problem). */
static afl_ret_t register_fuzz_worker(engine_t *engine) {

  // Critical section. Needs a lock. Called very rarely, thus won't affect perf.
  pthread_mutex_lock(&fuzz_worker_array_lock);
  
  if (fuzz_workers_count >= MAX_WORKERS) {
    pthread_mutex_unlock(&fuzz_worker_array_lock); 
    return AFL_RET_ARRAY_END; }

  registered_fuzz_workers[fuzz_workers_count] = engine;
  fuzz_workers_count++;
  // Unlock the mutex
  pthread_mutex_unlock(&fuzz_worker_array_lock);
  return AFL_RET_SUCCESS;

}

void *afl_insert_substring(
    u8 *buf, size_t len, void *token, size_t token_len,
    size_t offset);  // Returns new buf containing the substring token
int    rand_below(size_t limit);
size_t afl_erase_bytes(
    u8 *buf, size_t len, size_t offset,
    size_t remove_len);  // Erases remove_len number of bytes from offset
u8 *afl_insert_bytes(u8 *buf, size_t len, u8 byte,
                     size_t insert_len,  // Inserts a certain length of a byte
                                         // value (byte) at offset in buf
                     size_t offset);

static char **argv_cpy_dup(int argc, char **argv) {

  int i = 0;

  char **ret = calloc(1, (argc + 1) * sizeof(char *));

  for (i = 0; i < argc; i++) {

    ret[i] = strdup(argv[i]);

  }

  ret[i] = NULL;

  return ret;

}

#endif

