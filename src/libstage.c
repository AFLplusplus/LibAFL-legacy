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

void _afl_stage_init_(stage_t *stage, engine_t *engine) {

  stage->engine = engine;

  // We also add this stage to the engine's fuzzone

  engine->fuzz_one->funcs.add_stage(engine->fuzz_one, stage);

}

void afl_stage_deinit(stage_t *stage) {

  ck_free(stage);

}

fuzzing_stage_t *afl_fuzz_stage_init(engine_t *engine) {

  fuzzing_stage_t *fuzz_stage = ck_alloc(sizeof(fuzzing_stage_t));

  afl_stage_init(&(fuzz_stage->base), engine);

  fuzz_stage->funcs.add_mutator_to_stage = add_mutator_to_stage_default;

  return fuzz_stage;

}

void afl_fuzz_stage_deinit(fuzzing_stage_t *stage) {

  ck_free(stage);

}

void add_mutator_to_stage_default(fuzzing_stage_t *stage, void *mutator) {

  list_append(&(stage->mutators), mutator);

}

