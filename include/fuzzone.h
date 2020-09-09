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

#include "common.h"

struct fuzz_one_functions {

  afl_ret_t (*perform)(fuzz_one_t *);
  afl_ret_t (*add_stage)(fuzz_one_t *, stage_t *);
  afl_ret_t (*set_engine_default)(fuzz_one_t *, engine_t *);

};

struct fuzz_one {

  engine_t *engine;
  stage_t **stages;
  size_t    stages_count;

  struct fuzz_one_functions funcs;

};

afl_ret_t afl_perform_default(fuzz_one_t *);
afl_ret_t afl_add_stage_default(fuzz_one_t *, stage_t *);
afl_ret_t afl_set_engine_default(fuzz_one_t *, engine_t *);

afl_ret_t afl_fuzz_one_init(fuzz_one_t *, engine_t *);
void      afl_fuzz_one_deinit(fuzz_one_t *);

static inline fuzz_one_t *afl_fuzz_one_new(engine_t *engine) {

  fuzz_one_t *fuzz_one = calloc(1, sizeof(fuzz_one_t));
  if (!fuzz_one) { return NULL; }
  if (afl_fuzz_one_init(fuzz_one, engine) != AFL_RET_SUCCESS) {

    free(fuzz_one);
    return NULL;

  };

  return fuzz_one;

}

static inline void afl_fuzz_one_delete(fuzz_one_t *fuzz_one) {

  afl_fuzz_one_deinit(fuzz_one);

  free(fuzz_one);

}

#endif

