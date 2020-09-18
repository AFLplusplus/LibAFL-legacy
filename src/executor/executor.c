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

#include "executor/executor.h"

afl_ret_t afl_executor_init(afl_executor_t *executor) {

  memset(executor, 0, sizeof(afl_executor_t));
  executor->current_input = NULL;
  executor->observors = NULL;
  executor->observors_count = 0;

  // Default implementations of the functions
  executor->funcs.init_cb = NULL;
  executor->funcs.destroy_cb = NULL;
  executor->funcs.place_input_cb = NULL;
  executor->funcs.run_target_cb = NULL;
  executor->funcs.observer_add = afl_executor_add_observer;
  executor->funcs.observers_reset = afl_observers_reset;

  return AFL_RET_SUCCESS;

}

// Default implementations for executor vtable
void afl_executor_deinit(afl_executor_t *executor) {

  size_t i;
  executor->current_input = NULL;

  for (i = 0; i < executor->observors_count; i++) {

    afl_observer_deinit(executor->observors[i]);

  }

  afl_free(executor->observors);
  executor->observors = NULL;

  executor->observors_count = 0;

}

afl_ret_t afl_executor_add_observer(afl_executor_t *executor, afl_observer_t *obs_channel) {

  executor->observors_count++;

  executor->observors = afl_realloc(executor->observors, executor->observors_count * sizeof(afl_observer_t *));
  if (!executor->observors) { return AFL_RET_ALLOC; }
  executor->observors[executor->observors_count - 1] = obs_channel;

  return AFL_RET_SUCCESS;

}

afl_input_t *afl_executor_get_current_input(afl_executor_t *executor) {

  return executor->current_input;

}

void afl_observers_reset(afl_executor_t *executor) {

  size_t i;
  for (i = 0; i < executor->observors_count; ++i) {

    afl_observer_t *obs_channel = executor->observors[i];
    if (obs_channel->funcs.reset) { obs_channel->funcs.reset(obs_channel); }

  }

}
