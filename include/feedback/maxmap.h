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

#ifndef LIBAFL_FEEDBACK_MAXMAP_H
#define LIBAFL_FEEDBACK_MAXMAP_H

#include "object.h"
#include "error.h"

#include "feedback/feedback.h"
#include "observation_channel/map.h"

// TODO define with macros for different datatypes

typedef struct afl_maxmap_feedback afl_maxmap_feedback_t;

extern struct afl_feedback_vtable afl_maxmap_feedback_vtable_instance;

struct afl_maxmap_feedback {

  AFL_INHERITS(afl_feedback)
  
  afl_map_observation_channel_t* observation_channel;
  
  u8* virgin_map;
  size_t size;

};

/*
  Initialize an empty, just allocated, afl_maxmap_feedback_t object.
*/
afl_ret_t afl_maxmap_feedback_init(afl_maxmap_feedback_t *, afl_map_observation_channel_t*);

/*
  Deinit an afl_maxmap_feedback_t object, you must call this method before releasing
  the memory used by the object.
*/
void afl_maxmap_feedback_deinit__nonvirtual(afl_object_t *self);

static inline void afl_maxmap_feedback_deinit(afl_maxmap_feedback_t *self) {

  afl_feedback_deinit(AFL_BASEOF(self));

}

float afl_maxmap_feedback_is_interesting__nonvirtual(afl_feedback_t *self, afl_executor_t* executor);

static inline float afl_maxmap_feedback_is_interesting(afl_maxmap_feedback_t *self, afl_executor_t* executor) {

  return afl_feedback_is_interesting(BASE_CAST(self), executor);

}

AFL_NEW_FOR_WITH_PARAMS(afl_maxmap_feedback, AFL_DECL_PARAMS(afl_map_observation_channel_t* observation_channel), AFL_CALL_PARAMS(observation_channel))
AFL_DELETE_FOR(afl_maxmap_feedback)

#endif

