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

#include "libfuzzone.h"
#include "libengine.h"
#include "libqueue.h"
#include "list.h"

fuzz_one_t *afl_fuzz_one_init(engine_t *engine) {

  fuzz_one_t *fuzz_one = ck_alloc(sizeof(fuzz_one_t));
  fuzz_one->engine = engine;

  // We also add the fuzzone to the engine here.
  engine->fuzz_one = fuzz_one;
  fuzz_one->functions = ck_alloc(sizeof(struct fuzz_one_functions));

  fuzz_one->functions->add_stage = _add_stage_;
  fuzz_one->functions->perform = _perform_;

  return fuzz_one;

}

void _perform_(fuzz_one_t *fuzz_one) {

  engine_t *      engine = engine;
  global_queue_t *g_queue = engine->functions->get_queue(engine);

  queue_entry_t *entry = g_queue->super.functions->get_next_in_queue(g_queue);

  raw_input_t *original = entry->functions->get_input(entry);
  raw_input_t *input = original->functions->copy(original);

  // Implement the rest after Stage is created.

}

void _add_stage_(fuzz_one_t *fuzz_one, stage_t *stage) {

  list_append(&(fuzz_one->stages), stage);

}

