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

#include "libcommon.h"
#include "afl-returns.h"

typedef struct observation_channel observation_channel_t;

// vtable for the observation channel

struct observation_channel_functions {

  void (*flush)(observation_channel_t *);
  void (*reset)(observation_channel_t *);
  void (*post_exec)(observation_channel_t *);

};

struct observation_channel {

  // Can we have anything else here?
  struct observation_channel_functions funcs;

};

/* They're void now, but I think post_exec should have some return type? Since,
 * they'll mostly be implemented by user */
void flush_default(observation_channel_t *);
void reset_default(observation_channel_t *);
void post_exec(observation_channel_t *);
// Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.

afl_ret_t afl_observation_channel_init(observation_channel_t *);
void      afl_observation_channel_deinit(observation_channel_t *);

/* Function to create and destroy a new observation channel, allocates memory
  and initializes it. In destroy, it first deinitializes the struct and then
  frees it. */
static inline observation_channel_t *afl_observation_channel_create() {

  observation_channel_t *new_obs_channel =
      calloc(1, sizeof(observation_channel_t));
  if (!new_obs_channel) return NULL;
  if (afl_observation_channel_init(new_obs_channel) != AFL_RET_SUCCESS) {

    return NULL;

  };

  return new_obs_channel;

}

static inline void afl_observation_channel_delete(
    observation_channel_t *observation_channel) {

  afl_observation_channel_deinit(observation_channel);

  free(observation_channel);

}

typedef struct map_based_channel map_based_channel_t;

struct map_based_channel_functions {

  u8 *(*get_trace_bits)(map_based_channel_t *);
  size_t (*get_map_size)(map_based_channel_t *);

};

struct map_based_channel {

  observation_channel_t base;  // Base observation channel "class"

  afl_sharedmem_t shared_map;

  struct map_based_channel_functions extra_funcs;

};

u8 *   get_trace_bits_default(map_based_channel_t *obs_channel);
size_t get_map_size_default(map_based_channel_t *obs_channel);

// Functions to initialize and delete a map based observation channel

afl_ret_t afl_map_channel_init(map_based_channel_t *, size_t);
void      afl_map_channel_deinit(map_based_channel_t *);

static inline map_based_channel_t *afl_map_channel_create(size_t map_size) {

  map_based_channel_t *map_channel = calloc(1, sizeof(map_based_channel_t));
  if (!map_channel) { return NULL; }

  if (afl_map_channel_init(map_channel, map_size) == AFL_RET_ERROR_INITIALIZE) {

    return NULL;

  }

  return map_channel;

}

static inline void afl_map_channel_delete(map_based_channel_t *map_channel) {

  afl_map_channel_deinit(map_channel);

  free(map_channel);

}

#endif

