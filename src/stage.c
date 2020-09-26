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

#include "stage.h"
#include "engine.h"
#include "fuzzone.h"
#include "mutator.h"

afl_ret_t afl_stage_init(afl_stage_t *stage, afl_engine_t *engine) {

  stage->engine = engine;

  // We also add this stage to the engine's fuzzone
  if (engine) { engine->fuzz_one->funcs.add_stage(engine->fuzz_one, stage); }

  stage->funcs.get_iters = afl_stage_get_iters;
  stage->funcs.perform = afl_stage_perform;
  stage->funcs.add_mutator_to_stage = afl_stage_add_mutator;

  return AFL_RET_SUCCESS;

}

void afl_stage_deinit(afl_stage_t *stage) {

  stage->engine = NULL;

  for (size_t i = 0; i < stage->mutators_count; ++i) {

    afl_mutator_deinit(stage->mutators[i]);

  }

  afl_free(stage->mutators);
  stage->mutators = NULL;

}

afl_ret_t afl_stage_add_mutator(afl_stage_t *stage, afl_mutator_t *mutator) {

  if (!stage || !mutator) { return AFL_RET_NULL_PTR; }

  stage->mutators_count++;
  stage->mutators = afl_realloc(stage->mutators, stage->mutators_count * sizeof(afl_mutator_t *));
  if (!stage->mutators) { return AFL_RET_ALLOC; }

  stage->mutators[stage->mutators_count - 1] = mutator;

  return AFL_RET_SUCCESS;

}

size_t afl_stage_get_iters(afl_stage_t *stage) {

  return (1 + afl_rand_below(&stage->engine->rand, 128));

}

afl_ret_t afl_stage_run(afl_stage_t *stage, afl_input_t *input, bool overwrite) {

  afl_input_t *copy;
  if (!overwrite)
    copy = input->funcs.copy(input);
  else
    copy = input;

  /* Let's post process the mutated data now. */
  size_t j;
  for (j = 0; j < stage->mutators_count; ++j) {

    afl_mutator_t *mutator = stage->mutators[j];

    if (mutator->funcs.post_process) { mutator->funcs.post_process(mutator, copy); }

  }

  afl_ret_t ret = stage->engine->funcs.execute(stage->engine, copy);

  if (!overwrite) afl_input_delete(copy);

  return ret;

}

float afl_stage_is_interesting(afl_stage_t *stage) {

  float interestingness = 0.0f;

  afl_feedback_t **feedbacks = stage->engine->feedbacks;
  size_t           j;
  for (j = 0; j < stage->engine->feedbacks_count; ++j) {

    interestingness += feedbacks[j]->funcs.is_interesting(feedbacks[j], stage->engine->executor);

  }

  return interestingness;

}

/* Perform default for fuzzing stage */
afl_ret_t afl_stage_perform(afl_stage_t *stage, afl_input_t *input) {

  // size_t i;
  // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.

  size_t num = stage->funcs.get_iters(stage);

  for (size_t i = 0; i < num; ++i) {

    afl_input_t *copy = input->funcs.copy(input);
    if (!copy) { return AFL_RET_ERROR_INPUT_COPY; }

    size_t j;
    for (j = 0; j < stage->mutators_count; ++j) {

      afl_mutator_t *mutator = stage->mutators[j];
      // If the mutator decides not to fuzz this input, don't fuzz it. This is to support the custom mutator API of
      // AFL++
      if (mutator->funcs.custom_queue_get) {

        mutator->funcs.custom_queue_get(mutator, copy);
        continue;

      }

      if (mutator->funcs.trim) {

        size_t orig_len = copy->len;
        size_t trim_len = mutator->funcs.trim(mutator, copy);

        if (trim_len > orig_len) { return AFL_RET_TRIM_FAIL; }

      }

      mutator->funcs.mutate(mutator, copy);

    }

    afl_ret_t ret = afl_stage_run(stage, copy, true);

    /* Let's collect some feedback on the input now */
    float interestingness = afl_stage_is_interesting(stage);

    if (interestingness >= 0.5) {

      /* TODO: Use queue abstraction instead */
      llmp_message_t *msg = llmp_client_alloc_next(stage->engine->llmp_client, copy->len + sizeof(afl_entry_info_t));
      if (!msg) {

        DBG("Error allocating llmp message");
        return AFL_RET_ALLOC;

      }

      memcpy(msg->buf, copy->bytes, copy->len);

      /* TODO FIXME - here we fill in the entry info structure on the queue */
      // afl_entry_info_t *info_ptr = (afl_entry_info_t*)((u8*)(msg->buf + copy->len));
      // e.g. fill map hash

      msg->tag = LLMP_TAG_NEW_QUEUE_ENTRY_V1;
      if (!llmp_client_send(stage->engine->llmp_client, msg)) {

        DBG("An error occurred sending our previously allocated msg");
        return AFL_RET_UNKNOWN_ERROR;

      }

      /* we don't add it to the queue but wait for it to come back from the broker for now.
      TODO: Tidy this up. */
      interestingness = 0.0f;

    }

    /* If the input is interesting and there is a global queue add the input to
     * the queue */
    /* TODO: 0.5 is a random value. How do we want to chose interesting input? */
    if (interestingness >= 0.5 && stage->engine->global_queue) {

      afl_input_t *input_copy = copy->funcs.copy(copy);

      if (!input_copy) { return AFL_RET_ERROR_INPUT_COPY; }

      afl_entry_t *entry = afl_entry_new(input_copy, NULL);

      if (!entry) { return AFL_RET_ALLOC; }

      afl_queue_global_t *queue = stage->engine->global_queue;

      queue->base.funcs.insert((afl_queue_t *)queue, entry);

    }

    afl_input_delete(copy);

    switch (ret) {

      case AFL_RET_SUCCESS:
        continue;
      // We'll add more cases here based on the type of exit_ret value given by
      // the executor.Those will be handled in the engine itself.
      default:
        return ret;

    }

  }

  return AFL_RET_SUCCESS;

}

