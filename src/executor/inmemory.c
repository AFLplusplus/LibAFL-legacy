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

#include "executor/inmemory.h"

struct afl_executor_vtable afl_inmemory_executor_vtable_instance = {

  .destroy = &afl_executor_destroy;
  .run_target = &afl_inmemory_executor_run_target;
  .place_input = &afl_inmemory_executor_place_input;

};

void afl_inmemory_executor_init(afl_inmemory_executor_t *self, afl_harness_function_t harness_function) {

  DCHECK(self);
  DCHECK(harness_function);

  afl_executor_init__protected(BASE_CAST(self));

  self->harness_function = harness_function;
  self->argv = NULL;
  self->argc = 0;

  BASE_CAST(self)->v = &afl_inmemory_executor_vtable_instance;

}

u8 afl_inmemory_executor_place_input(afl_executor_t *self, afl_input_t *input) {

  DCHECK(self);
  DCHECK(input);

  // TODO do it in afl_executor
  self->current_input = input;
  return 0;

}

afl_exit_t afl_inmemory_executor_run_target(afl_executor_t *self) {

  DCHECK(self);
  DCHECK(INSTANCE_OF(afl_inmemory_executor, self));

  afl_inmemory_executor_t *e = (afl_inmemory_executor_t *)self;

  u8 *data;
  size_t size;

  afl_input_serialize(self->current_input, &data, &size); // TODO check if serialize accocated mem

  return e->harness_function(self, data, size);

}
