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

#ifndef LIBAFL_EXECUTOR_EXECUTOR_H
#define LIBAFL_EXECUTOR_EXECUTOR_H

#include "object.h"
#include "error.h"

#include "observation_channel/observation_channel.h"
#include "input/input.h"

typedef struct afl_executor afl_executor_t;

struct afl_executor_vtable {

  AFL_VTABLE_INHERITS(afl_object)

  /*
    The run_target() method is mandatory.
  */
  afl_exit_t (*run_target)(afl_executor_t *);

  /*
    The place_input() method is optional. It has a default implementation.
  */
  u8 (*place_input)(afl_executor_t *, afl_input_t *);

};

extern struct afl_executor_vtable afl_executor_vtable_instance;

/*
  An Executor is an entity with a set of violation oracles, a set of observation channels, a function that allows
  instructing the SUT about the input to test, and a function to run the SUT.
*/
struct afl_executor {

  AFL_INHERITS(afl_object)

  afl_observation_channel_t *observation_channels;
  u32                        observation_channels_count;

  //afl_oracle_t *oracles;
  //u32           oracles_count;

  afl_input_t *current_input;

};

/*
  Initialize an empty, just allocated, afl_executor_t object.
  Virtual class, protected init.
*/
afl_ret_t afl_executor_init__protected(afl_executor_t *);

/*
  Add an afl_observation_channel_t to the list.
*/
afl_ret_t afl_executor_add_observation_channel(afl_executor_t *, afl_observation_channel_t *);

/*
  Reset the state of all the observation channels.
*/
void afl_executor_reset_observation_channels(afl_executor_t *);

/*
  Add an afl_observation_channel_t to the list.
*/
//afl_ret_t afl_executor_add_oracle(afl_executor_t *, afl_oracle_t *);

/*
  Deinit an afl_executor_t object, you must call this method before releasing
  the memory used by the object.
*/
void afl_executor_deinit__nonvirtual(afl_object_t *);

static inline void afl_executor_deinit(afl_executor_t *self) {

  afl_object_deinit(AFL_BASEOF(self));

}

/*
  Run the target represented by the executor.
*/
static inline afl_exit_t afl_executor_run_target(afl_executor_t *self) {

  DCHECK(self);
  DCHECK(AFL_VTABLEOF(afl_executor, self)->run_target);

  return AFL_VTABLEOF(afl_executor, self)->run_target(self);

}

/*
  Instruct the SUT about the input.
*/
static inline u8 afl_executor_place_input__nonvirtual(afl_executor_t *self, afl_input_t *input) {

  self->current_input = input;
  return AFL_RET_SUCCESS;

}

static inline u8 afl_executor_place_input(afl_executor_t *self, afl_input_t *input) {

  DCHECK(self);
  DCHECK(input);
  DCHECK(AFL_VTABLEOF(afl_executor, self)->place_input);

  return AFL_VTABLEOF(afl_executor, self)->place_input(self, input);

}

AFL_DELETE_FOR(afl_executor)

#endif

