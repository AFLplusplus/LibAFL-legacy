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

#include "executor/inmemory.h"

/* An in-mem executor we have */

void in_memory_executor_init(in_memory_executor_t *in_memory_executor, harness_function_type harness) {

  afl_executor_init(&in_memory_executor->base);
  in_memory_executor->harness = harness;
  in_memory_executor->argv = NULL;
  in_memory_executor->argc = 0;

  in_memory_executor->base.funcs.run_target_cb = in_memory_run_target;
  in_memory_executor->base.funcs.place_input_cb = in_mem_executor_place_input;

}

void in_memory_executor_deinit(in_memory_executor_t *in_memory_executor) {

  afl_executor_deinit(&in_memory_executor->base);
  in_memory_executor->harness = NULL;
  in_memory_executor->argv = NULL;
  in_memory_executor->argc = 0;

  in_memory_executor->base.funcs.run_target_cb = in_memory_run_target;
  in_memory_executor->base.funcs.place_input_cb = in_mem_executor_place_input;

}

u8 in_mem_executor_place_input(afl_executor_t *executor, afl_input_t *input) {

  executor->current_input = input;
  return 0;

}

afl_exit_t in_memory_run_target(afl_executor_t *executor) {

  in_memory_executor_t *in_memory_executor = (in_memory_executor_t *)executor;

  afl_input_t *input = in_memory_executor->base.current_input;

  u8 *data = (input->funcs.serialize) ? (input->funcs.serialize(input)) : input->bytes;

  afl_exit_t run_result = in_memory_executor->harness(&in_memory_executor->base, data, input->len);

  return run_result;

}
