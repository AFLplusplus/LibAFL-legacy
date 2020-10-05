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

#ifndef LIBAFL_STAGE_STAGE_H
#define LIBAFL_STAGE_STAGE_H

#include "object.h"
#include "error.h"

#include "engine/engine.h"

typedef struct afl_stage afl_stage_t;

struct afl_stage_vtable {

  /*
    The deinit() method is optional.
    It is invoked just before the destroy of the object.
  */
  void (*deinit)(afl_stage_t *);

  /*
    The perform() method is mandatory.
  */
  void (*perform)(afl_stage_t *, afl_input_t*, afl_input*);
  
};

struct afl_stage {

  INHERITS(afl_object)
  
  struct afl_stage_vtable *v;

};

/*
  Initialize an empty, just allocated, afl_stage_t object.
  Virtual class, protected init.
*/
afl_ret_t afl_stage_init__protected(afl_stage_t *);

/*
  Deinit an afl_stage_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_stage_deinit(afl_stage_t *self) {

  DCHECK(self);
  DCHECK(self->v);

  if (self->v->deinit) self->v->deinit(self);

}

static inline float afl_stage_perform(afl_stage_t *self, afl_input_t* input, afl_input_t* original) {

  DCHECK(self);
  DCHECK(self->v);
  DCHECK(self->v->perform);

  return self->v->perform(self, input, original);

}

AFL_DELETE_FOR(afl_stage)

#endif

