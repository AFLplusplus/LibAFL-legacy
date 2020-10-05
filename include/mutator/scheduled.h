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

#ifndef LIBAFL_MUTATOR_SCHEDULED_H
#define LIBAFL_MUTATOR_SCHEDULED_H

#include "object.h"
#include "error.h"
#include "rand.h"

#include "mutator/mutator.h"

extern struct afl_mutator_vtable afl_scheduled_mutator_vtable_instance;

typedef struct afl_scheduled_mutator afl_scheduled_mutator_t;

typedef void (*afl_mutation_function_t)(afl_mutator_t *, afl_input_t *);

struct afl_scheduled_mutator_vtable {

  /*
    The iterations() method is optional. It has a default implementation.
  */
  u32 (*iterations)(afl_scheduled_mutator_t *, afl_input_t*);

  /*
    The schedule() method is optional. It has a default implementation.
  */
  u32 (*schedule)(afl_scheduled_mutator_t *, afl_input_t*);

};

struct afl_scheduled_mutator {

  INHERITS(afl_mutator)

  afl_mutation_function_t *mutations;
  size_t                   mutations_count;

  struct afl_scheduled_mutator_vtable *v;

};

/*
  Initialize an empty, just allocated, afl_scheduled_mutator_t object.
*/
afl_ret_t afl_scheduled_mutator_init(afl_scheduled_mutator_t *);

/*
  Add a mutation to the mutator.
*/
void afl_scheduled_mutator_add_mutation(afl_scheduled_mutator_t *, afl_mutation_function_t *);

/*
  Get the number of mutations to apply.
*/
static inline u32 afl_scheduled_mutator_iterations__nonvirtual_protected(afl_scheduled_mutator_t *self, afl_input_t* input) {

  return 1 << (1 + (u32)RAND_BELOW(7));

}

static inline u32 afl_scheduled_mutator_iterations(afl_scheduled_mutator_t *self, afl_input_t* input) {

  DCHECK(self);
  
  if(self->v->iterations)
    return self->v->iterations(self, input);

  return afl_scheduled_mutator_iterations__nonvirtual_protected(self, input);  

}

/*
  Get the next mutation to apply (as index).
*/
static inline u32 afl_scheduled_mutator_schedule__nonvirtual_protected(afl_scheduled_mutator_t *self, afl_input_t* input) {
  
  return (u32)RAND_BELOW(self->mutations_count);
  
}

static inline u32 afl_scheduled_mutator_schedule(afl_scheduled_mutator_t *self, afl_input_t* input) {

  DCHECK(self);
  
  if(self->v->schedule)
    return self->v->schedule(self, input);

  return afl_scheduled_mutator_schedule__nonvirtual_protected(self, input);

}

/*
  Destroy the context of an afl_scheduled_mutator_t.
*/
void afl_scheduled_mutator_destroy(afl_mutator_t * self);

/*
  Mutate an input.
*/
static inline u32 afl_scheduled_mutator_mutate(afl_mutator_t *self, afl_input_t *input, u32 stage_idx) {

  (void)stage_idx;

  DCHECK(self);
  DCHECK(INSTANCE_OF(afl_scheduled_mutator, self));

  u32 i, num;

  afl_scheduled_mutator_t *s = (afl_scheduled_mutator *)self;
  num = afl_scheduled_mutator_iterations(s, input);
  for (i = 0; i < num; ++i) {

    s->mutations[afl_scheduled_mutator_schedule(s, input)](self, input);

  }

}

AFL_NEW_FOR(afl_scheduled_mutator)

#endif

