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

#include "libmutator.h"

void _afl_mutator_init_(mutator_t *mutator, stage_t *stage) {

  mutator->stage = stage;

  mutator->funcs.get_stage = get_mutator_stage_default;
  mutator->funcs.init = mutator_init_default;
  mutator->funcs.mutate = mutate_default;
  mutator->funcs.trim = trim_default;

}

void afl_mutator_deinit(mutator_t *mutator) {

  free(mutator);

}

stage_t *get_mutator_stage_default(mutator_t *mutator) {

  return mutator->stage;

}

void mutator_init_default(mutator_t *mutator) {

  /* TODO: Implementation */
  return;

};

size_t trim_default(mutator_t *mutator, u8 *mem, u8 *new_mem) {

  /* TODO: Implementation */
  return 0;

};

size_t mutate_default(mutator_t *mutator, raw_input_t *input, size_t size) {

  /* TODO: Implementation */
  return 0;

};

scheduled_mutator_t *afl_scheduled_mutator_init(stage_t *stage) {

  scheduled_mutator_t *sched_mut = ck_alloc(sizeof(scheduled_mutator_t));
  afl_mutator_init(&(sched_mut->super), stage);


  sched_mut->extra_funcs.add_mutator = add_mutator_default;
  sched_mut->extra_funcs.iterations = iterations_default;
  sched_mut->extra_funcs.schedule = schedule_default;

  return sched_mut;

}

void afl_scheduled_mutator_deinit(scheduled_mutator_t *mutator) {

  LIST_FOREACH_CLEAR(&(mutator->mutations), mutator_func_type, {});

  free(mutator);

}

void add_mutator_default(scheduled_mutator_t *mutator,
                   mutator_func_type    mutator_func) {

  list_append(&(mutator->mutations), mutator_func);

}

int  iterations_default(scheduled_mutator_t * mutator) {

  /* TODO: Implementation */
  return 0;

};

int schedule_default(scheduled_mutator_t *mutator) {

  /* TODO: Implementation */
  return 0;

};

