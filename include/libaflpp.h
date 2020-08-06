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

#ifndef AFL_FILE_INCLUDED
#define AFL_FILE_INCLUDED

#include "libcommon.h"
#include "libobservationchannel.h"
#include "libinput.h"
#include "list.h"
#include "libos.h"
#include <types.h>
#include "afl-returns.h"

#define MAX_OBS_CHANNELS 5

/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/

struct executor_functions {

  afl_ret_t (*init_cb)(executor_t *);     // can be NULL
  u8 (*destroy_cb)(executor_t *);  // can be NULL

  exit_type_t (*run_target_cb)(
      executor_t *);  // Similar to afl_fsrv_run_target we have in afl
  u8 (*place_input_cb)(
      executor_t *,
      raw_input_t *);  // similar to the write_to_testcase function in afl.

  observation_channel_t *(*get_observation_channels)(
      executor_t *, size_t);  // Getter function for observation channels list

  u8 (*add_observation_channel)(
      executor_t *,
      observation_channel_t *);  // Add an observtion channel to the list

  raw_input_t *(*get_current_input)(
      executor_t *);  // Getter function for the current input

  void (*reset_observation_channels)(
      executor_t *);  // Reset the observation channels

};

// This is like the generic vtable for the executor.

struct executor {

  observation_channel_t
      *observors[MAX_OBS_CHANNELS];  // This will be swapped for the observation
                                     // channel once its ready

  u32 observors_num;

  raw_input_t *current_input;  // Holds current input for the executor

  struct executor_functions funcs;  // afl executor_ops;

};

list_t afl_executor_list;  // We'll be maintaining a list of executors.

void _afl_executor_init_(executor_t *);
void afl_executor_deinit(executor_t *);
u8   add_observation_channel_default(executor_t *, observation_channel_t *);
observation_channel_t *get_observation_channels_default(executor_t *, size_t);
raw_input_t *          get_current_input_default(executor_t *);
void                   reset_observation_channel_default(executor_t *);

// Function used to initialize an executor, pass a NULL ptr if you want a new
// base executor, pass the base executor if you already have inherited it and
// allocated mem for it. Returns the initialized executor on success, and NULL
// on error.

static inline executor_t *afl_executor_init(executor_t *executor) {

  executor_t *new_executor = executor;

  if (executor)
    _afl_executor_init_(executor);

  else {

    new_executor = calloc(1, sizeof(executor_t));
    if (!new_executor) return NULL;
    _afl_executor_init_(new_executor);

  }

  return new_executor;

}

#define AFL_EXECUTOR_DEINIT(executor) afl_executor_deinit(executor);

enum {

  AFL_PLACE_INPUT_MISSING = 1  // 1

};

#endif

