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

 */

#include "libengine.h"

void _afl_engine_init_(engine_t *engine) {

  engine->funcs.get_queue = get_queue_default;
  engine->funcs.get_execs = get_execs_defualt;
  engine->funcs.get_fuzz_one = get_fuzz_one_default;
  engine->funcs.get_start_time = get_start_time_default;

  engine->funcs.set_fuzz_one = set_fuzz_one_default;
  engine->funcs.add_feedback = add_feedback_default;
  engine->funcs.increase_execs = increase_execs_default;

}

void afl_engine_deinit(engine_t *engine) {

  free(engine);

  /* TODO: Should we free everything else like feedback, etc with engine too */

}

global_queue_t *get_queue_default(engine_t *engine) {

  return engine->global_queue;

}

fuzz_one_t *get_fuzz_one_default(engine_t *engine) {

  return engine->fuzz_one;

}

u64 get_execs_defualt(engine_t *engine) {

  return engine->executions;

}

u64 get_start_time_default(engine_t *engine) {

  return engine->start_time;

}

void set_fuzz_one_default(engine_t *engine, fuzz_one_t *fuzz_one) {

  engine->fuzz_one = fuzz_one;

}

void increase_execs_default(engine_t *engine) {

  engine->executions++;

}

int add_feedback_default(engine_t *engine, feedback_t *feedback) {

  if (engine->feedbacks_num >= MAX_FEEDBACKS) return 1;

  engine->feedbacks_num++;

  engine->feedbacks[(engine->feedbacks_num - 1)] = feedback;

  return 0;

}

