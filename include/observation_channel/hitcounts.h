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

#ifndef LIBAFL_OBSERVATION_CHANNEL_MAP_H
#define LIBAFL_OBSERVATION_CHANNEL_MAP_H

#include "object.h"
#include "error.h"

#include "observation_channel/map.h"

typedef struct afl_hitcounts_observation_channel afl_hitcounts_observation_channel_t;

extern struct afl_observation_channel_vtable afl_hitcounts_observation_channel_vtable_instance;

struct afl_hitcounts_observation_channel {

  AFL_INHERITS(afl_map_observation_channel)

};

/*
  Initialize an empty, just allocated, afl_hitcounts_observation_channel_t object.
  Virtual class, protected init.
*/
static inline afl_ret_t afl_hitcounts_observation_channel_init(afl_hitcounts_observation_channel_t * self, u8* trace_map, size_t size) {

  afl_ret_t r = afl_map_observation_channel_init(AFL_BASEOF(self), trace_map, size);
  VTABLE_SET(self, afl_hitcounts_observation_channel_vtable_instance);
  return r;

}

/*
  Deinit an afl_hitcounts_observation_channel_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_hitcounts_observation_channel_deinit(afl_hitcounts_observation_channel_t *self) {

  afl_observation_channel_deinit(AFL_BASEOF(self));

}

static inline void afl_hitcounts_observation_channel_flush(afl_hitcounts_observation_channel_t *self) {

  afl_observation_channel_flush(AFL_BASEOF(self))

}

static inline void afl_hitcounts_observation_channel_reset(afl_hitcounts_observation_channel_t *self) {

  afl_observation_channel_reset(AFL_BASEOF(self))

}

void afl_hitcounts_observation_channel_post_exec__nonvirtual(afl_observation_channel_t *self, afl_executor_t* executor);

static inline void afl_hitcounts_observation_channel_post_exec(afl_hitcounts_observation_channel_t *self, afl_executor_t* executor) {

  afl_observation_channel_post_exec(AFL_BASEOF(self), executor);

}

AFL_NEW_FOR_WITH_PARAMS(afl_hitcounts_observation_channel, AFL_DECL_PARAMS(u8* trace_map, size_t size), AFL_CALL_PARAMS(trace_map, size))
AFL_DELETE_FOR(afl_hitcounts_observation_channel)

#endif

