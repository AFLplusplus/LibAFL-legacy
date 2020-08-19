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

#include "queue.h"
#include "fuzzone.h"
#include "engine.h"
#include "stage.h"
#include "list.h"

afl_ret_t afl_fuzz_one_init(fuzz_one_t *fuzz_one, engine_t *engine) {

  fuzz_one->engine = engine;

  if (engine) { engine->fuzz_one = fuzz_one; }

  fuzz_one->funcs.add_stage = afl_add_stage_default;
  fuzz_one->funcs.perform = afl_perform_default;
  fuzz_one->funcs.add_engine_default = afl_add_engine_default;

  return AFL_RET_SUCCESS;

}

void afl_fuzz_one_deinit(fuzz_one_t *fuzz_one) {

  /* Also remove the fuzz one from engine */
  fuzz_one->engine = NULL;

  /* TODO: Should we deinitialize the stages or just remove the reference of
   * fuzzone from them? */
  for (size_t i = 0; i < fuzz_one->stages_num; ++i) {

    fuzz_one->stages[i] = NULL;

  }

  fuzz_one->stages_num = 0;

}

afl_ret_t afl_perform_default(fuzz_one_t *fuzz_one) {

  // Fuzzone grabs the current queue entry from one of many global queues and
  // sends it to stage.

  if (!fuzz_workers_count) { return AFL_RET_NO_FUZZ_WORKERS; }
  global_queue_t *global_queue =
      registered_fuzz_workers[afl_rand_below_engine(fuzz_one->engine,
                                                    fuzz_workers_count)]
          ->global_queue;

  queue_entry_t *queue_entry = global_queue->base.funcs.get_next_in_queue(
      (base_queue_t *)global_queue, fuzz_one->engine->id);

  if (!queue_entry) { return AFL_RET_NULL_QUEUE_ENTRY; }

  /* Fuzz the entry with every stage */
  for (size_t i = 0; i < fuzz_one->stages_num; ++i) {

    stage_t * current_stage = fuzz_one->stages[i];
    afl_ret_t stage_ret =
        current_stage->funcs.perform(current_stage, queue_entry->input);

    switch (stage_ret) {

      case AFL_RET_SUCCESS:
        continue;
      default:
        return stage_ret;

    }

  }

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_add_stage_default(fuzz_one_t *fuzz_one, stage_t *stage) {

  if (!stage || !fuzz_one) { return AFL_RET_NULL_PTR; }

  if (fuzz_one->stages_num >= MAX_STAGES) return AFL_RET_ARRAY_END;

  fuzz_one->stages_num++;

  fuzz_one->stages[(fuzz_one->stages_num - 1)] = stage;
  stage->engine = fuzz_one->engine;

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_add_engine_default(fuzz_one_t *fuzz_one, engine_t *engine) {

  fuzz_one->engine = engine;

  for (size_t i = 0; i < fuzz_one->stages_num; ++i) {

    fuzz_one->stages[i]->engine = engine;

  }

  return AFL_RET_SUCCESS;

}

