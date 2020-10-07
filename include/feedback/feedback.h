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

#ifndef LIBAFL_FEEDBACK_FEEDBACK_H
#define LIBAFL_FEEDBACK_FEEDBACK_H

#include "object.h"
#include "error.h"

#include "executor/executor.h"
#include "corpus/corpus.h"

typedef struct afl_feedback afl_feedback_t;

struct afl_feedback_vtable {

  AFL_VTABLE_INHERITS(afl_object)

  /*
    The is_interesting() method is mandatory.
  */
  float (*is_interesting)(afl_feedback_t *, afl_executor_t*);
  
};

extern struct afl_feedback_vtable afl_feedback_vtable_instance;

struct afl_feedback {

  AFL_INHERITS(afl_object)
  
  afl_corpus_t* specific_corpus;

};

/*
  Initialize an empty, just allocated, afl_feedback_t object.
  Virtual class, protected init.
*/
afl_ret_t afl_feedback_init__protected(afl_feedback_t *);

/*
  Deinit an afl_feedback_t object, you must call this method before releasing
  the memory used by the object.
*/
// void afl_feedback_deinit__nonvirtual(afl_object_t *self);

static inline void afl_feedback_deinit(afl_feedback_t *self) {

  afl_object_deinit(AFL_BASEOF(self));

}

/*
  Determinate if the current input is interesting.
*/
static inline float afl_feedback_is_interesting(afl_feedback_t *self, afl_executor_t* executor) {

  DCHECK(self);
  DCHECK(AFL_VTABLEOF(afl_feedback, self));
  DCHECK(AFL_VTABLEOF(afl_feedback, self)->is_interesting);

  return AFL_VTABLEOF(afl_feedback, self)->is_interesting(self, executor);

}

AFL_DELETE_FOR(afl_feedback)

#endif
