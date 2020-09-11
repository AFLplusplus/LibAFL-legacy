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

#ifndef LIBSTAGE_H
#define LIBSTAGE_H

#include "input.h"

struct stage_functions {

  afl_ret_t (*perform)(afl_stage_t *, afl_input_t *input);
  size_t (*iterations)(afl_stage_t *);  // A function which tells how many mutated
                                    // inputs to generate out of a given input

};

struct afl_stage {

  afl_engine_t *         engine;
  struct stage_functions funcs;

};

afl_ret_t afl_perform_stage(afl_stage_t *, afl_input_t *);
size_t    afl_iterations_stage(afl_stage_t *);
afl_ret_t afl_stage_init(afl_stage_t *, afl_engine_t *);
void      afl_stage_deinit(afl_stage_t *);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_stage, AFL_DECL_PARAMS(afl_engine_t *engine), AFL_CALL_PARAMS(engine))

/*
This structure here represents a single fuzzing stage in  the process. e.g It
can be used to model a single fuzzing stage in AFL++, like the determinisitc
phase, or the havoc phase. Since each of the stages can have their own mutators,
a list of mutators can be added to the stage.
*/

typedef struct fuzzing_stage afl_fuzzing_stage_t;

struct fuzzing_stage_functions {

  /* Change the void pointer to a mutator * once it is ready */
  afl_ret_t (*add_mutator_to_stage)(afl_fuzzing_stage_t *, afl_mutator_t *);

};

struct fuzzing_stage {

  /* Standard "inheritence" from stage */
  afl_stage_t base;
  /* The list of mutator operators that this stage has */
  afl_mutator_t **mutators;

  struct fuzzing_stage_functions funcs;
  size_t                         mutators_count;

};

afl_ret_t afl_add_mutator_to_stage(afl_fuzzing_stage_t *, afl_mutator_t *);

afl_ret_t afl_fuzzing_stage_init(afl_fuzzing_stage_t *, afl_engine_t *);
void      afl_fuzzing_stage_deinit(afl_fuzzing_stage_t *);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_fuzzing_stage, AFL_DECL_PARAMS(afl_engine_t *engine), AFL_CALL_PARAMS(engine))

#endif

