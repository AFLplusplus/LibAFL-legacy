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

#ifndef LIBFUZZONE_H
#define LIBFUZZONE_H

#include "types.h"
#include "common.h"

struct afl_fuzz_one_funcs {

  afl_ret_t (*perform)(afl_fuzz_one_t *);
  afl_ret_t (*add_stage)(afl_fuzz_one_t *, afl_stage_t *);
  afl_ret_t (*set_engine)(afl_fuzz_one_t *, afl_engine_t *);

};

struct afl_fuzz_one {

  afl_engine_t *engine;
  afl_stage_t **stages;
  size_t        stages_count;

  struct afl_fuzz_one_funcs funcs;

};

afl_ret_t afl_fuzz_one_perform(afl_fuzz_one_t *);
afl_ret_t afl_fuzz_one_add_stage(afl_fuzz_one_t *, afl_stage_t *);
afl_ret_t afl_fuzz_one_set_engine(afl_fuzz_one_t *, afl_engine_t *);

afl_ret_t afl_fuzz_one_init(afl_fuzz_one_t *, afl_engine_t *);
void      afl_fuzz_one_deinit(afl_fuzz_one_t *);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_fuzz_one, AFL_DECL_PARAMS(afl_engine_t *engine), AFL_CALL_PARAMS(engine))

#endif

