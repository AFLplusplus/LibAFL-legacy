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

#include "libqueue.h"
#include "libfuzzone.h"
#include "libengine.h"
#include "libstage.h"
#include "list.h"

#define UNUSED(x) (void)(x)

void _afl_fuzz_one_init_(fuzz_one_t *fuzz_one, engine_t *engine) {

  fuzz_one->engine = engine;

  fuzz_one->funcs.add_stage = add_stage_default;
  fuzz_one->funcs.perform = perform_default;

}

void afl_fuzz_one_deinit(fuzz_one_t *fuzz_one) {

  for (size_t i = 0; i < fuzz_one->stages_num; ++i) {

    AFL_STAGE_DEINIT(fuzz_one->stages[i]);

  }

  free(fuzz_one);

};

int perform_default(fuzz_one_t *fuzz_one) {

  UNUSED(fuzz_one);

  // Fuzzone grabs the current queue entry from global queue and sends it to stage.
  global_queue_t * global_queue = fuzz_one->engine->funcs.get_queue(fuzz_one->engine);

  queue_entry_t * queue_entry = global_queue->base.funcs.get_next_in_queue((base_queue_t *)global_queue);

  /* Fuzz the entry with every stage */
  for (size_t i = 0; i < fuzz_one->stages_num; ++i) {

    stage_t * current_stage = fuzz_one->stages[i];
    current_stage->funcs.perform(current_stage, queue_entry->funcs.get_input(queue_entry));

  }

  return 0;

}

int add_stage_default(fuzz_one_t *fuzz_one, stage_t *stage) {

  if (fuzz_one->stages_num >= MAX_STAGES) return 1;

  fuzz_one->stages_num++;

  fuzz_one->stages[(fuzz_one->stages_num - 1)] = stage;

  return 0;

}

