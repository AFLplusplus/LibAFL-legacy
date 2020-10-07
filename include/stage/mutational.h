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

#include "stage/stage.h"
#include "entry/entry.h"
#include "engine/engine.h"

typedef struct afl_mutational_stage afl_mutational_stage_t;

struct afl_mutational_stage_vtable {

  AFL_VTABLE_INHERITS(afl_stage_vtable)

  /*
    The perform() method is optional. It has a default implementation.
  */
  u32 (*iterations)(afl_mutational_stage_t *, afl_entry_t*);

};

extern struct afl_mutational_stage_vtable afl_mutational_stage_vtable_instance;

struct afl_mutational_stage {

  AFL_INHERITS(afl_stage)
  
  afl_mutator_t** mutators;
  u32 mutators_count;
  
};

/*
  Initialize an empty, just allocated, afl_mutational_stage_t object.
*/
afl_ret_t afl_mutational_stage_init(afl_mutational_stage_t *);

/*
  Add a mutator to the stage.
*/
void afl_mutational_stage_add_mutator(afl_mutational_stage_t *self, afl_mutator_t* mutator);

/*
  Deinit an afl_stage_t object, you must call this method before releasing
  the memory used by the object.
*/
void afl_mutational_stage_deinit__nonvirtual(afl_object_t *self);

static inline void afl_mutational_stage_deinit(afl_mutational_stage_t *self) {

  afl_stage_deinit(AFL_BASEOF(self));

}

/*
  Get how many iterations the stage must perform.
*/
static inline u32 afl_mutational_stage_iterations__nonvirtual(afl_mutational_stage_t *self, afl_entry_t* entry) {
  
  (void)entry;

  return (1 + (u32)AFL_RAND_BELOW(128));

}

static inline u32 afl_mutational_stage_iterations(afl_mutational_stage_t *self, afl_entry_t* entry) {

  DCHECK(self);
  DCHECK(AFL_VTABLEOF(afl_mutational_stage, self));
  
  if(AFL_VTABLEOF(afl_mutational_stage, self)->iterations)
    return AFL_VTABLEOF(afl_mutational_stage, self)->iterations(self, entry);

  return afl_mutational_stage_iterations__nonvirtual(self, entry);  

}

static inline void afl_mutational_stage_perform__nonvirtual(afl_stage_t *self, afl_input_t* input, afl_entry_t* entry) {

  DCHECK(self);
  DCHECK(AFL_ISNTANCEOF(afl_mutational_stage, self));
  DCHECK(input);
  DCHECK(entry);
  
  afl_mutational_stage_t* s = (afl_mutational_stage_t*)self;
  afl_input_t* original = afl_entry_load_input(entry);
  
  u32 i, j, num = afl_mutational_stage_iterations(s, entry);
  
  for (i = 0; i < num; ++i) {
  
    for (j = 0; j < s->mutators_count; ++j)
      afl_mutator_mutate(s->mutators[j], input);
      
    afl_engine_execute(s->engine, input);
    
    afl_input_assign(input, original);
  
  }

}

static inline void afl_mutational_stage_perform(afl_mutational_stage_t *self, afl_input_t* input, afl_entry_t* entry) {

  afl_stage_perform(AFL_BASEOF(self), input, entry);

}

AFL_NEW_FOR(afl_mutational_stage)
AFL_DELETE_FOR(afl_mutational_stage)

#endif

