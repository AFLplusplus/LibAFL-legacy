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

#include "libstage.h"
#include "libengine.h"
#include "libfuzzone.h"
#include "libmutator.h"

void _afl_stage_init_internal(stage_t *stage, engine_t *engine) {

  stage->engine = engine;

  // We also add this stage to the engine's fuzzone

  engine->fuzz_one->funcs.add_stage(engine->fuzz_one, stage);

  stage->funcs.iterations = iterations_stage_default;

}

void afl_stage_deinit(stage_t *stage) {

  /* We*/

  free(stage);

}

fuzzing_stage_t *afl_fuzz_stage_init(engine_t *engine) {

  fuzzing_stage_t *fuzz_stage = calloc(sizeof(fuzzing_stage_t), 1);

  afl_stage_init(&(fuzz_stage->base), engine);

  fuzz_stage->funcs.add_mutator_to_stage = add_mutator_to_stage_default;
  fuzz_stage->base.funcs.perform = perform_stage_default;

  return fuzz_stage;

}

void afl_fuzz_stage_deinit(fuzzing_stage_t *stage) {

  /* We free the mutators associated with the stage here */

  for (size_t i = 0; i < stage->mutators_count; ++i) {

    AFL_MUTATOR_DEINIT(stage->mutators[i]);

  }

  free(stage);

}

afl_ret_t add_mutator_to_stage_default(fuzzing_stage_t *stage,
                                       mutator_t *      mutator) {

  if (!stage && !mutator) { return AFL_RET_NULL_PTR; }

  if (stage->mutators_count >= MAX_STAGE_MUTATORS) { return AFL_RET_ARRAY_END; }

  stage->mutators[stage->mutators_count] = mutator;
  stage->mutators_count++;

  return AFL_RET_SUCCESS;

}

size_t iterations_stage_default(stage_t *stage) {

  (void)stage;
  return (1 + rand_below(128));

}

/* Perform default for fuzzing stage */
afl_ret_t perform_stage_default(stage_t *stage, raw_input_t *input) {

  // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
  fuzzing_stage_t *fuzz_stage = (fuzzing_stage_t *)stage;

  size_t num = fuzz_stage->base.funcs.iterations(stage);

  SAYF("Iteration to be done %ld times\n", num);

  for (size_t i = 0; i < num; ++i) {

    raw_input_t *copy = input->funcs.copy(input);

    for (size_t j = 0; j < fuzz_stage->mutators_count; ++j) {

      mutator_t *mutator = fuzz_stage->mutators[j];
      mutator->funcs.mutate(mutator, copy);

    }

    afl_ret_t ret = stage->engine->funcs.execute(stage->engine, copy);

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

};

