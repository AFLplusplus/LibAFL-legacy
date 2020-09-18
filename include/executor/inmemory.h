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

#include "executor.h"

/* In-memory executor */

// TODO rename to afl_in_memory_executor, names must be coherent!!!

/* Function ptr for the harness */
typedef afl_exit_t (*harness_function_type)(afl_executor_t *executor, u8 *, size_t);

typedef struct in_memeory_executor {

  afl_executor_t        base;
  harness_function_type harness;
  char **               argv;  // These are to support the libfuzzer harnesses
  int                   argc;  // To support libfuzzer harnesses

} in_memory_executor_t;

afl_exit_t in_memory_run_target(afl_executor_t *executor);
u8         in_mem_executor_place_input(afl_executor_t *executor, afl_input_t *input);
void       in_memory_executor_init(in_memory_executor_t *in_memeory_executor, harness_function_type harness);

#endif
