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

#ifndef OBSERVATION_FILE_INCLUDED
#define OBSERVATION_FILE_INCLUDED

#include "libcommon.h"

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

void _afl_observation_channel_init_(observation_channel_t *);
void afl_observation_channel_deinit(observation_channel_t *);

static inline observation_channel_t *afl_observation_channel_init(
    observation_channel_t *obs_channel) {

  observation_channel_t *new_obs_channel = obs_channel;

  if (obs_channel)
    _afl_observation_channel_init_(obs_channel);

  else {

    new_obs_channel = calloc(1, sizeof(observation_channel_t));
    if (!new_obs_channel) return NULL;
    _afl_observation_channel_init_(new_obs_channel);

  }

  return new_obs_channel;

}

#define AFL_OBSERVATION_CHANNEL_DEINIT(obs_channel) \
  afl_observation_channel_deinit(obs_channel);

typedef struct map_based_channel map_based_channel_t;

struct map_based_channel_functions {

  u8 *(*get_trace_bits)(map_based_channel_t *);
  size_t (*get_map_size)(map_based_channel_t *);

};

struct map_based_channel {

  observation_channel_t super;  // Base observation channel "class"

  afl_sharedmem_t *shared_map;

  struct map_based_channel_functions extra_funcs;

};

u8 *   get_trace_bits_default(map_based_channel_t *obs_channel);
size_t get_map_size_default(map_based_channel_t *obs_channel);

// Functions to initialize and delete a map based observation channel

map_based_channel_t *afl_map_channel_init(size_t);
void                 afl_map_channel_deinit(map_based_channel_t *);

#endif
