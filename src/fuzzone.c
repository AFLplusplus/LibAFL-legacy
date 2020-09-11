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

afl_ret_t afl_fuzz_one_init(afl_fuzz_one_t *fuzz_one, afl_engine_t *engine) {

  fuzz_one->engine = engine;

  if (engine) { engine->fuzz_one = fuzz_one; }

  fuzz_one->funcs.add_stage = afl_add_stage;
  fuzz_one->funcs.perform = afl_perform;
  fuzz_one->funcs.set_engine = afl_set_engine;

  return AFL_RET_SUCCESS;

}

void afl_fuzz_one_deinit(afl_fuzz_one_t *fuzz_one) {

  size_t i;
  /* Also remove the fuzz one from engine */
  fuzz_one->engine = NULL;

  /* TODO: Should we deinitialize the stages or just remove the reference of
   * fuzzone from them? */
  for (i = 0; i < fuzz_one->stages_count; ++i) {

    fuzz_one->stages[i] = NULL;

  }

  afl_free(fuzz_one->stages);
  fuzz_one->stages = NULL;
  fuzz_one->stages_count = 0;

}

afl_ret_t afl_perform(afl_fuzz_one_t *fuzz_one) {

  // Fuzzone grabs the current queue entry from the global queue and
  // sends it to stage.
  size_t i;

  afl_queue_global_t *global_queue = fuzz_one->engine->global_queue;

  afl_entry_t *queue_entry =
      global_queue->base.funcs.get_next_in_queue((afl_queue_t *)global_queue, fuzz_one->engine->id);

  if (!queue_entry) { return AFL_RET_NULL_QUEUE_ENTRY; }

  /* Fuzz the entry with every stage */
  for (i = 0; i < fuzz_one->stages_count; ++i) {

    afl_stage_t *current_stage = fuzz_one->stages[i];
    afl_ret_t    stage_ret = current_stage->funcs.perform(current_stage, queue_entry->input);

    switch (stage_ret) {

      case AFL_RET_SUCCESS:
        continue;
      default:
        return stage_ret;

    }

  }

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_add_stage(afl_fuzz_one_t *fuzz_one, afl_stage_t *stage) {

  if (!stage || !fuzz_one) { return AFL_RET_NULL_PTR; }

  fuzz_one->stages_count++;
  fuzz_one->stages = afl_realloc(fuzz_one->stages, fuzz_one->stages_count * sizeof(afl_stage_t *));
  if (!fuzz_one->stages) { return AFL_RET_ALLOC; }

  fuzz_one->stages[fuzz_one->stages_count - 1] = stage;

  stage->engine = fuzz_one->engine;

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_set_engine(afl_fuzz_one_t *fuzz_one, afl_engine_t *engine) {

  size_t i;
  fuzz_one->engine = engine;

  if (engine) { engine->fuzz_one = fuzz_one; }

  for (i = 0; i < fuzz_one->stages_count; ++i) {

    fuzz_one->stages[i]->engine = engine;

  }

  return AFL_RET_SUCCESS;

}

