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

int _perform_(fuzz_one_t *fuzz_one) {

  // Implement after Stage is created.

  return 0;

}

int _add_stage_(fuzz_one_t *fuzz_one, stage_t *stage) {

  if (fuzz_one->stages_num >= MAX_STAGES) return 1;

  fuzz_one->stages_num++;

  fuzz_one->stages[(fuzz_one->stages_num - 1)] = stage;

  return 0;

}

