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

#ifndef LIBOBSERVATIONCHANNEL_H
#define LIBOBSERVATIONCHANNEL_H

#include "common.h"
#include "shmem.h"
#include "afl-returns.h"

#define AFL_OBSERVER_TAG_BASE (0x0B5EB45E)
#define AFL_OBSERVER_TAG_COVMAP (0x0B5EC0FE)

typedef struct afl_observer afl_observer_t;

// vtable for the observation channel

struct afl_observer_funcs {

  void (*flush)(afl_observer_t *);
  void (*reset)(afl_observer_t *);
  void (*post_exec)(afl_observer_t *, afl_engine_t *);

};

struct afl_observer {

  u32 tag;
  struct afl_observer_funcs funcs;

};

/* They're void now, but I think post_exec should have some return type? Since,
 * they'll mostly be implemented by user */
void afl_observer_flush(afl_observer_t *);
void afl_observer_reset(afl_observer_t *);
void afl_observer_post_exec(afl_observer_t *);
// Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.

afl_ret_t afl_observer_init(afl_observer_t *channel);
void      afl_observer_deinit(afl_observer_t *);

/* Function to create and destroy a new observation channel, allocates memory
  and initializes it. In destroy, it first deinitializes the struct and then
  frees it. */

AFL_NEW_AND_DELETE_FOR(afl_observer)

typedef struct afl_observer_covmap afl_observer_covmap_t;

struct afl_observer_covmap_funcs {

  u8 *(*get_trace_bits)(afl_observer_covmap_t *);
  size_t (*get_map_size)(afl_observer_covmap_t *);

};

struct afl_observer_covmap {

  afl_observer_t base;  // Base observation channel "class"

  afl_shmem_t shared_map;

  struct afl_observer_covmap_funcs funcs;

};

u8 *   afl_observer_covmap_get_trace_bits(afl_observer_covmap_t *obs_channel);
size_t afl_observer_covmap_get_map_size(afl_observer_covmap_t *obs_channel);

// Functions to initialize and delete a map based observation channel

afl_ret_t afl_observer_covmap_init(afl_observer_covmap_t *, size_t map_size);
void      afl_observer_covmap_deinit(afl_observer_covmap_t *);
void      afl_observer_covmap_reset(afl_observer_t *);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_observer_covmap, AFL_DECL_PARAMS(size_t map_size), AFL_CALL_PARAMS(map_size))

#endif

