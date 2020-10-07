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

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */

#ifndef LIBAFL_STAGE_MUTATIONAL_H
#define LIBAFL_STAGE_MUTATIONAL_H

#include "object.h"
#include "error.h"

#include "engine/engine.h"

extern struct afl_stage_vtable afl_mutational_stage_vtable_instance;

typedef struct afl_mutational_stage afl_mutational_stage_t;

struct afl_mutational_stage_vtable {

  /*
    The perform() method is optional. It has a default implementation.
  */
  u32 (*iterations)(afl_mutational_stage_t *, afl_input_t*);

};

struct afl_mutational_stage {

  INHERITS(afl_stage)
  
  afl_mutator_t** mutators;
  u32 mutators_count;
  
  struct afl_mutational_stage_vtable* v;
  
};

/*
  Initialize an empty, just allocated, afl_stage_t object.
  Virtual class, protected init.
*/
afl_ret_t afl_stage_init__protected(afl_stage_t *);

/*
  Add a mutator to the stage.
*/
void afl_mutational_stage_add_mutator(afl_mutational_stage_t *self, afl_mutator_t* mutator);

/*
  Deinit an afl_stage_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_mutational_stage_deinit(afl_stage_t *self) {

  afl_stage_deinit(BASE_CAST(self));

}

static inline float afl_mutational_stage_perform(afl_mutational_stage_t *self, afl_input_t* input, afl_input_t* original) {

  return afl_stage_perform(BASE_CAST(self), input, original);

}

/*
  Get how many iterations the stage must perform.
*/
static inline u32 afl_mutational_stage_iterations__nonvirtual(afl_scheduled_mutator_t *self, afl_input_t* input) {
  
  (void)input;

  return (1 + (u32)RAND_BELOW(128));

}

static inline u32 afl_mutational_stage_iterations(afl_scheduled_mutator_t *self, afl_input_t* input) {

  DCHECK(self);
  
  if(self->v->iterations)
    return self->v->iterations(self, input);

  return afl_mutational_stage_iterations__nonvirtual(self, input);  

}

AFL_NEW_FOR(afl_stage)
AFL_DELETE_FOR(afl_stage)

#endif

