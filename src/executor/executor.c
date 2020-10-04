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

#include "executor/executor.h"

afl_ret_t afl_executor_init__protected(afl_executor_t *self) {

  self->current_input = NULL;
  
  self->observation_channels = NULL;
  self->observation_channels_count = 0;
  
  self->oracles = NULL;
  self->oracles_count = 0;
  
  return AFL_RET_SUCCESS;

}

void afl_executor_destroy(afl_executor_t *self) {

  size_t i;
  for (i = 0; i < self->observation_channels_count; i++)
    afl_observation_channel_deinit(self->observation_channels[i]);

  afl_free(self->observation_channels);
  self->observation_channels = NULL;

  self->observation_channels_count = 0;
  
  for (i = 0; i < self->oracles_count; i++)
    afl_oracle_deinit(self->oracles[i]);

  afl_free(executor->oracles);
  self->oracles = NULL;

  self->oracles_count = 0;

}

afl_ret_t afl_executor_add_observation_channel(afl_executor_t *self, afl_observation_channel_t *obs_channel) {

  afl_observation_channel_t* o = afl_realloc(executor->observation_channels, (executor->observation_channels_count +1) * sizeof(afl_observation_channel_t *));
  if (!o) return AFL_RET_ALLOC;
  
  executor->observation_channels = o;
  executor->observation_channels[executor->observation_channels_count] = obs_channel;
  self->observation_channels_count++;

  return AFL_RET_SUCCESS;

}

void afl_executor_reset_observation_channels(afl_executor_t *executor) {

  size_t i;
  for (i = 0; i < executor->observation_channels_count; ++i) {

    afl_observation_channel_t *o = executor->observation_channels[i];
    if (o->funcs.reset) o->funcs.reset(o);

  }

}

afl_ret_t afl_executor_add_oracle(afl_executor_t *self, afl_oracle_t *oracle) {

  afl_oracle_t* o = afl_realloc(executor->oracles, (executor->oracles_count +1) * sizeof(afl_oracle_t *));
  if (!o) return AFL_RET_ALLOC;
  
  executor->oracles = o;
  executor->oracles[executor->oracles_count] = oracle;
  self->oracles_count++;

  return AFL_RET_SUCCESS;

}
