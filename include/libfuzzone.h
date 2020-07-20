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

#ifndef FUZZONE_FILE_INCLUDED
#define FUZZONE_FILE_INCLUDED

#include "libcommon.h"
#include "list.h"

#define MAX_STAGES 5

struct fuzz_one {

  engine_t *engine;
  stage_t * stages[MAX_STAGES];
  u64       stages_num;

  struct fuzz_one_functions *functions;

};

struct fuzz_one_functions {

  int (*perform)(fuzz_one_t *);
  int (*add_stage)(fuzz_one_t *, stage_t *);

};

int _perform_(fuzz_one_t *);
int _add_stage_(fuzz_one_t *, stage_t *);

void afl_fuzz_one_init(fuzz_one_t *, engine_t *);
void afl_fuzz_one_deinit(fuzz_one_t *);

static inline fuzz_one_t *AFL_FUZZ_ONE_INIT(fuzz_one_t *fuzzone,
                                            engine_t *  engine) {

  fuzz_one_t *new_fuzzone = NULL;

  if (fuzzone)
    afl_fuzz_one_init(fuzzone, engine);

  else {

    new_fuzzone = ck_alloc(sizeof(fuzz_one_t));
    afl_fuzz_one_init(new_fuzzone, engine);

  }

  return new_fuzzone;

}

#define AFL_FUZZ_ONE_DEINIT(fuzzone) afl_fuzz_one_deinit(fuzzone);

#endif

