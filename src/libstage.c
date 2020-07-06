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

stage_t *afl_stage_init(engine_t *engine) {

  stage_t *stage = ck_alloc(sizeof(stage_t));
  stage->operations = ck_alloc(sizeof(struct stage_operations));

  stage->engine = engine;

  // We also add this stage to the engine's fuzzone

  list_append(&(engine->fuzz_one->stages), stage);

  return stage;

}

void afl_stage_deinit(stage_t *stage) {

  ck_free(stage->operations);
  ck_free(stage);

}

fuzzing_stage_t *afl_fuzz_stage_init(engine_t *engine) {

  fuzzing_stage_t *fuzz_stage = ck_alloc(sizeof(fuzzing_stage_t));

  fuzz_stage->super = *(afl_stage_init(engine));

  fuzz_stage->operations = ck_alloc(sizeof(struct fuzzing_stage_operations));

  fuzz_stage->operations->add_mutator = _add_mutator_;

  return fuzz_stage;

}

void afl_fuzz_stage_deinit(fuzzing_stage_t *stage) {

  ck_free(stage->operations);
  ck_free(stage);

}

void _add_mutator_(fuzzing_stage_t *stage, void *mutator) {

  list_append(&(stage->mutators), mutator);

}

