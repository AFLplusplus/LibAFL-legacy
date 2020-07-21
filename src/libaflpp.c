/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the actual code for the library framework.

 */

#include "libaflpp.h"
#include "list.h"
#include "stdbool.h"
#include "afl-errors.h"

void afl_executor_init(executor_t *executor) {

  executor->current_input = NULL;

  // Default implementations of the functions
  executor->funcs.add_observation_channel = _add_observation_channel_;
  executor->funcs.get_observation_channels = _get_observation_channels_;
  executor->funcs.get_current_input = _get_current_input_;

}

// Default implementations for executor vtable
void afl_executor_deinit(executor_t *executor) {

  if (!executor) FATAL("Cannot free a NULL pointer");

  ck_free(executor);

}

u8 _add_observation_channel_(executor_t *           executor,
                             observation_channel_t *obs_channel) {

  list_append(&executor->observors, obs_channel);

  return 0;

}

list_t _get_observation_channels_(executor_t *executor) {

  return executor->observors;

}

raw_input_t *_get_current_input_(executor_t *executor) {

  return executor->current_input;

}

// Functions to allocate and deallocate the standard feedback structs

/* This is the primary function for the entire library, for each executor, we
would pass it to this function which start fuzzing it, something similar to what
afl_fuzz's main function does.
This will be the entrypoint of a new thread when it is created (for each
executor instance).*/
u8 fuzz_start(executor_t *executor) {

  /* TODO: Implementation yet to be done based on design changes. Will be moved
   * to fuzz_one */
  return 0;

}

