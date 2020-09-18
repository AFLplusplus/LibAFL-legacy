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

#ifndef LIBAFL_EXECUTOR_EXECUTOR_H
#define LIBAFL_EXECUTOR_EXECUTOR_H

#include <types.h>

#include "afl-returns.h"
#include "observer.h"
#include "input.h"

/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/

struct afl_executor_funcs {

  afl_ret_t (*init_cb)(afl_executor_t *);  // can be NULL
  u8 (*destroy_cb)(afl_executor_t *);      // can be NULL

  afl_exit_t (*run_target_cb)(afl_executor_t *);          // Similar to afl_fsrv_run_target we have in afl
  u8 (*place_input_cb)(afl_executor_t *, afl_input_t *);  // similar to the write_to_testcase function in afl.

  afl_ret_t (*observer_add)(afl_executor_t *, afl_observer_t *);  // Add an observtion channel to the list

  afl_input_t *(*input_get)(afl_executor_t *);  // Getter function for the current input

  void (*observers_reset)(afl_executor_t *);  // Reset the observation channels

};

// This is like the generic vtable for the executor.

struct afl_executor {

  afl_observer_t **observors;  // This will be swapped for the observation channel once its ready

  u32 observors_count;

  afl_input_t *current_input;  // Holds current input for the executor

  struct afl_executor_funcs funcs;  // afl executor_ops;

};

afl_ret_t    afl_executor_init(afl_executor_t *);
void         afl_executor_deinit(afl_executor_t *);
afl_ret_t    afl_executor_add_observer(afl_executor_t *, afl_observer_t *);
afl_input_t *afl_executor_get_current_input(afl_executor_t *);
void         afl_observers_reset(afl_executor_t *);

// Function used to create an executor, we alloc the memory ourselves and
// initialize the executor

AFL_NEW_AND_DELETE_FOR(afl_executor)

#endif
