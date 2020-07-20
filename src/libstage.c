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

void afl_stage_init(stage_t *stage, engine_t *engine) {

  stage->functions = ck_alloc(sizeof(struct stage_functions));

  stage->engine = engine;

  // We also add this stage to the engine's fuzzone

  _add_stage_(engine->fuzz_one, stage);

}

void afl_stage_deinit(stage_t *stage) {

  ck_free(stage->functions);
  ck_free(stage);

}

fuzzing_stage_t *afl_fuzz_stage_init(engine_t *engine) {

  fuzzing_stage_t *fuzz_stage = ck_alloc(sizeof(fuzzing_stage_t));

  AFL_STAGE_INIT(&(fuzz_stage->super), engine);

  fuzz_stage->functions = ck_alloc(sizeof(struct fuzzing_stage_functions));

  fuzz_stage->functions->add_mutator_to_stage = _add_mutator_to_stage_;

  return fuzz_stage;

}

void afl_fuzz_stage_deinit(fuzzing_stage_t *stage) {

  ck_free(stage->functions);
  ck_free(stage);

}

void _add_mutator_to_stage_(fuzzing_stage_t *stage, void *mutator) {

  list_append(&(stage->mutators), mutator);

}

