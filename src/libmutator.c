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

void afl_mutator_init(mutator_t * mutator, stage_t *stage) {

  mutator->stage = stage;
  mutator->functions = ck_alloc(sizeof(struct mutator_functions));

  mutator->functions->get_stage = _get_mutator_stage_;

}

void afl_mutator_deinit(mutator_t *mutator) {

  ck_free(mutator->functions);
  ck_free(mutator);

}

stage_t *_get_mutator_stage_(mutator_t *mutator) {

  return mutator->stage;

}

scheduled_mutator_t *afl_scheduled_mutator_init(stage_t *stage) {

  scheduled_mutator_t *sched_mut = ck_alloc(sizeof(scheduled_mutator_t));
  AFL_MUTATOR_INIT(&(sched_mut->super), stage);
  sched_mut->extra_functions =
      ck_alloc(sizeof(struct scheduled_mutator_functions));

  sched_mut->extra_functions->add_mutator = _add_mutator_;
  sched_mut->extra_functions->iterations = _iterations_;
  sched_mut->extra_functions->schedule = _schedule_;

  return sched_mut;

}

void afl_scheduled_mutator_deinit(scheduled_mutator_t *mutator) {

  LIST_FOREACH_CLEAR(&(mutator->mutations), mutator_func_type, {});

  ck_free(mutator->extra_functions);
  ck_free(mutator);

}

void _add_mutator_(scheduled_mutator_t *mutator,
                   mutator_func_type    mutator_func) {

  list_append(&(mutator->mutations), mutator_func);

}

