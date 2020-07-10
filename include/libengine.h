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

#include "libaflpp.h"
#include "libfeedback.h"

struct engine {

  fuzz_one_t *    fuzz_one;
  global_queue_t *global_queue;
  executor_t *    executor;
  list_t          feedbacks;
  u64             executions, start_time;
  int             id;

  struct engine_functions *functions;

};

struct engine_functions {

  global_queue_t *(*get_queue)(engine_t *);
  fuzz_one_t *(*get_fuzz_one)(engine_t *);
  u64 (*get_execs)(engine_t *);
  u64 (*get_start_time)(engine_t *);

  void (*set_fuzz_one)(engine_t *, feedback_t);
  void (*increase_execs)(engine_t *);
  void (*add_feedback)(engine_t *, feedback_t *);

  void (*execute)(engine_t *, raw_input_t *);
  void (*load_testcases_from_dir)(engine_t *, u8 *);
  void (*load_zero_testcase)(size_t);

  void (*loop)();  // Not sure about this functions usa-case. Was in FFF though.

};

/* TODO: Add default implementations for load_testcases and execute */
global_queue_t *_get_queue_(engine_t *);
fuzz_one_t *    _get_fuzz_one_(engine_t *);
u64             _get_execs_(engine_t *);
u64             _get_start_time_(engine_t *);

void _set_fuzz_one_(engine_t *, fuzz_one_t *);
void _increase_execs_(engine_t *);
void _add_feedback_(engine_t *, feedback_t *);

void _execute_(engine_t *, raw_input_t *);
void _load_testcases_from_dir_(engine_t *, u8 *);
void _load_zero_testcase_(size_t);

void _loop_();  // Not sure about this functions usa-case. Was in FFF though.

engine_t *afl_engine_init();
void      afl_engine_deinit();

