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

#include "lib-common.h"

typedef struct observation_channel {

  struct observation_channel_operations *operations;

} observation_channel_t;

// vtable for the observation channel

struct observation_channel_operations {

  void (*flush)(observation_channel_t *);
  void (*reset)(observation_channel_t *);
  void (*post_exec)(observation_channel_t *);

};

// Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.

observation_channel_t *afl_obs_channel_init();
void                   afl_obs_channel_deinit();

typedef struct map_based_channel {

  observation_channel_t super;  // Base observation channel "class"

  afl_sharedmem_t *shared_map;

  struct map_based_channel_operations *extra_ops;

} map_based_channel_t;

struct map_based_channel_operations {

  u8 *(*get_trace_bits)(map_based_channel_t *);
  size_t (*get_map_size)(map_based_channel_t *);

};

u8 *   _get_trace_bits_(map_based_channel_t *obs_channel);
size_t _get_map_size_(map_based_channel_t *obs_channel);

// Functions to initialize and delete a map based observation channel

map_based_channel_t *afl_map_channel_init(size_t);
void                 afl_map_channel_deinit(map_based_channel_t *);

