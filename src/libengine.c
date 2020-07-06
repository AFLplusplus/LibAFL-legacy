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

engine_t *afl_engine_init() {

  engine_t *engine = ck_alloc(sizeof(engine_t));
  engine->operations = ck_alloc(sizeof(struct engine_operations));
  engine->operations->get_queue = _get_queue_;
  engine->operations->get_execs = _get_execs_;
  engine->operations->get_fuzz_one = _get_fuzz_one_;
  engine->operations->get_start_time = _get_start_time_;

  engine->operations->set_fuzz_one = _set_fuzz_one_;
  engine->operations->add_feedback = _add_feedback_;
  engine->operations->increase_execs = _increase_execs_;

  return engine;

}

void afl_engine_deinit(engine_t *engine) {

  ck_free(engine->operations);

  ck_free(engine);

  /* TODO: Should we free everything else liek feedback, etc with engine too */

}

global_queue_t *_get_queue_(engine_t *engine) {

  return engine->global_queue;

}

fuzz_one_t *_get_fuzz_one_(engine_t *engine) {

  return engine->fuzz_one;

}

u64 _get_execs_(engine_t *engine) {

  return engine->executions;

}

u64 _get_start_time_(engine_t *engine) {

  return engine->start_time;

}

void _set_fuzz_one_(engine_t *engine, fuzz_one_t *fuzz_one) {

  engine->fuzz_one = fuzz_one;

}

void _increase_execs_(engine_t *engine) {

  engine->executions++;

}

void _add_feedback_(engine_t *engine, feedback_t *feedback) {

  list_append(&engine->feedbacks, feedback);

}

