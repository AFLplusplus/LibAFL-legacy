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

#ifndef LIBAFL_MUTATOR_MUTATOR_H
#define LIBAFL_MUTATOR_MUTATOR_H

#include "object.h"
#include "error.h"

typedef struct afl_mutator afl_mutator_t;

struct afl_mutator_vtable {

  /*
    The deinit() method is optional.
    It is invoked just before the destroy of the object.
  */
  void (*deinit)(afl_mutator_t *);

  /*
    The mutate() method is mandatory.
  */
  void (*mutate)(afl_mutator_t *, afl_input_t *, u32);

  // TBD
  // void (*merge)(afl_mutator_t * self, afl_input_t ** inputs, size_t inputs_count);

};

/*
  A Mutator is an entity that takes one or more inputs and generates a new derived one.
*/
struct afl_mutator {

  INHERIT(afl_object)

  struct afl_mutator_vtable *v;

};

/*
  Deinit an afl_input_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_mutator_deinit__nonvirtual(afl_mutator_t *self) {}

static inline void afl_mutator_deinit(afl_mutator_t *self) {

  DCHECK(self);
  DCHECK(self->v);

  if (self->v->deinit)
    self->v->deinit(self);
  else
    afl_mutator_deinit__nonvirtual(self);

}

/*
  Deserialize the input from a bytes array.
*/
static inline void afl_mutator_mutate(afl_mutator_t *self, afl_input_t *input, u32 stage_idx) {

  DCHECK(self);
  DCHECK(self->v);
  DCHECK(self->v->mutate);

  return self->v->mutate(self, input, stage_idx);

}

AFL_DELETE_FOR(afl_input)

#endif

