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

#ifndef LIBAFL_EXECUTOR_INMEMORY_H
#define LIBAFL_EXECUTOR_INMEMORY_H

#include "object.h"
#include "error.h"

#include "executor/executor.h"

typedef afl_exit_t (*afl_harness_function_t)(afl_inmemory_executor_t *, u8 *, size_t);

typedef struct afl_inmemory_executor afl_inmemory_executor_t;

extern struct afl_executor_vtable afl_inmemory_executor_vtable_instance;

struct afl_inmemory_executor {

  INHERITS(afl_executor)

  afl_harness_function_t harness_function;

  /* libFuzzer compatibility */
  char **argv;
  int    argc;

};

/*
  Initialize an empty, just allocated, afl_inmemory_executor_t object.
*/
afl_ret_t afl_inmemory_executor_init(afl_inmemory_executor_t *, afl_harness_function_t);

/*
  Run thet harness function.
*/
afl_exit_t afl_inmemory_executor_run_target__nonvirtual(afl_executor_t *);

static inline afl_exit_t afl_inmemory_executor_run_target(afl_inmemory_executor_t * self) {

  return afl_executor_run_target(AFL_BASEOF(self));

}

/*
  Prepare harness arguments.
*/
static inline void afl_inmemory_executor_place_input(afl_inmemory_executor_t *self) {

  afl_executor_place_input(AFL_BASEOF(self));

}

/*
  Destroy the context of an afl_inmemory_executor_t.
*/
static inline void afl_inmemory_executor_deinit(afl_inmemory_executor_t *self) {

  afl_executor_deinit(AFL_BASEOF(self));

}

AFL_NEW_FOR_WITH_PARAMS(afl_inmemory_executor, AFL_DECL_PARAMS(afl_harness_function_t harness_function), AFL_CALL_PARAMS(harness_function))
AFL_DELETE_FOR(afl_inmemory_executor)

#endif

