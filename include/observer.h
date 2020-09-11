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

typedef struct observer afl_observer_t;

// vtable for the observation channel

struct observer_functions {

  void (*flush)(afl_observer_t *);
  void (*reset)(afl_observer_t *);
  void (*post_exec)(afl_observer_t *, afl_engine_t *);

};

struct observer {

  // Can we have anything else here?
  size_t                    channel_id;  // MUST be unique
  struct observer_functions funcs;

};

/* They're void now, but I think post_exec should have some return type? Since,
 * they'll mostly be implemented by user */
void afl_flush(afl_observer_t *);
void afl_reset(afl_observer_t *);
void afl_post_exec(afl_observer_t *);
// Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.

afl_ret_t afl_observer_init(afl_observer_t *, size_t);
void      afl_observer_deinit(afl_observer_t *);

/* Function to create and destroy a new observation channel, allocates memory
  and initializes it. In destroy, it first deinitializes the struct and then
  frees it. */
static inline afl_observer_t *afl_observer_new(size_t channel_id) {

  afl_observer_t *new_obs_channel = calloc(1, sizeof(afl_observer_t));
  if (!new_obs_channel) { return NULL; }
  if (afl_observer_init(new_obs_channel, channel_id) != AFL_RET_SUCCESS) {

    free(new_obs_channel);
    return NULL;

  };

  return new_obs_channel;

}

static inline void afl_observer_delete(afl_observer_t *observer) {

  afl_observer_deinit(observer);

  free(observer);

}

typedef struct map_based_channel afl_map_based_channel_t;

struct map_based_channel_functions {

  u8 *(*get_trace_bits)(afl_map_based_channel_t *);
  size_t (*get_map_size)(afl_map_based_channel_t *);

};

struct map_based_channel {

  afl_observer_t base;  // Base observation channel "class"

  afl_shmem_t shared_map;

  struct map_based_channel_functions funcs;

};

u8 *   afl_get_trace_bits(afl_map_based_channel_t *obs_channel);
size_t afl_get_map_size(afl_map_based_channel_t *obs_channel);

// Functions to initialize and delete a map based observation channel

afl_ret_t afl_map_channel_init(afl_map_based_channel_t *, size_t, size_t);
void      afl_map_channel_deinit(afl_map_based_channel_t *);
void      afl_map_channel_reset(afl_observer_t *);

static inline afl_map_based_channel_t *afl_map_channel_new(size_t map_size, size_t channel_id) {

  afl_map_based_channel_t *map_channel = calloc(1, sizeof(afl_map_based_channel_t));
  if (!map_channel) { return NULL; }

  if (afl_map_channel_init(map_channel, map_size, channel_id) == AFL_RET_ERROR_INITIALIZE) {

    free(map_channel);
    return NULL;

  }

  return map_channel;

}

static inline void afl_map_channel_delete(afl_map_based_channel_t *map_channel) {

  afl_map_channel_deinit(map_channel);

  free(map_channel);

}

#endif

