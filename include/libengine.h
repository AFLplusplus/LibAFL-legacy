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

   The Engine is the main and central part of the fuzzer. It contains the
   queues, feedbacks, executor and the fuzz_one (which in turn has stages)

 */

#ifndef LIBENGINE_H 
#define LIBENGINE_H

#include "libcommon.h"
#include "libqueue.h"
#include "libaflpp.h"
#include "libfeedback.h"
#include "afl-returns.h"

#define MAX_FEEDBACKS 10

struct engine_functions {

  global_queue_t *(*get_queue)(engine_t *);
  fuzz_one_t *(*get_fuzz_one)(engine_t *);
  u64 (*get_execs)(engine_t *);
  u64 (*get_start_time)(engine_t *);

  void (*set_fuzz_one)(engine_t *, fuzz_one_t *);
  int (*add_feedback)(engine_t *, feedback_t *);

  u8 (*execute)(engine_t *, raw_input_t *);
  afl_ret_t (*load_testcases_from_dir)(
      engine_t *, char *, raw_input_t *(*custom_input_init)(u8 *buf));
  void (*load_zero_testcase)(size_t);

  void (*loop)(engine_t *);  // Not sure about this functions usa-case. Was in
                             // FFF though.

};

struct engine {

  fuzz_one_t *      fuzz_one;
  global_queue_t *  global_queue;
  executor_t *      executor;
  feedback_queue_t *current_feedback_queue;
  feedback_t
      *feedbacks[MAX_FEEDBACKS];  // We're keeping a pointer of feedbacks here
                                  // to save memory, consideting the original
                                  // feedback would already be allocated
  u64 executions, start_time, feedbacks_num;
  int id;

  struct engine_functions funcs;

};

/* TODO: Add default implementations for load_testcases and execute */
global_queue_t *get_queue_default(engine_t *);
fuzz_one_t *    get_fuzz_one_default(engine_t *);
u64             get_execs_defualt(engine_t *);
u64             get_start_time_default(engine_t *);

void set_fuzz_one_default(engine_t *, fuzz_one_t *);
int  add_feedback_default(engine_t *, feedback_t *);

u8        execute_default(engine_t *, raw_input_t *);
afl_ret_t load_testcases_from_dir_default(
    engine_t *, char *, raw_input_t *(*custom_input_init)(u8 *buf));
void load_zero_testcase_default(size_t);

void loop_default(engine_t *);  // Not sure about this functions use-case. Was
                                // in FFF though.

void _afl_engine_init_(engine_t *, executor_t *, fuzz_one_t *,
                       global_queue_t *);
void afl_engine_deinit();

#define AFL_ENGINE_DEINIT(engine) afl_engine_deinit(engine);

static inline engine_t *afl_engine_init(engine_t *engine, executor_t *executor,
                                        fuzz_one_t *    fuzz_one,
                                        global_queue_t *global_queue) {

  engine_t *new_engine = engine;

  if (engine)
    _afl_engine_init_(engine, executor, fuzz_one, global_queue);

  else {

    new_engine = calloc(1, sizeof(engine_t));
    if (!new_engine) return NULL;
    _afl_engine_init_(new_engine, executor, fuzz_one, global_queue);

  }

  return new_engine;

}

#endif

