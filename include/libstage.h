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

#include "lib-common.h"
#include "libinput.h"
#include "list.h"

struct stage {

  engine_t *               engine;
  struct stage_operations *operations;

};

struct stage_operations {

  void (*perform)(raw_input_t *input, raw_input_t *original);

};

stage_t *afl_stage_init(engine_t *);
void     afl_stage_deinit(stage_t);

/*
This structure here represents a single fuzzing stage in  the process. e.g It
can be used to model a single fuzzing stage in AFL++, like the determinisitc
phase, or the havoc phase. Since each of the stages can have their own mutators,
a list of mutators can be added to the stage.
*/

typedef struct fuzzing_stage {

  stage_t super;  // Standard "inheritence" from stage

  list_t mutators;  // The list of mutator operators that this stage has

  struct fuzzing_stage_operations *operations;

} fuzzing_stage_t;

struct fuzzing_stage_operations {

  /* Change the void pointer to a mutator * once it is ready */
  void (*add_mutator)(fuzzing_stage_t *, void *);

};

void _add_mutator_(fuzzing_stage_t *, void *);

fuzzing_stage_t *afl_fuzz_stage_init(engine_t *);
void             afl_fuzzing_stage_deinit(fuzzing_stage_t *);

