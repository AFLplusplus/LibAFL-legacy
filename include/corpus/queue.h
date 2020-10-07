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

#ifndef LIBAFL_CORPUS_CORPUS_H
#define LIBAFL_CORPUS_CORPUS_H

#include "object.h"
#include "error.h"
#include "rand.h"

#include "corpus/entry.h"

typedef struct afl_queue_corpus afl_queue_corpus_t;

extern struct afl_corpus_vtable afl_queue_corpus_vtable_instance;

struct afl_queue_corpus {

  AFL_INHERITS(afl_corpus)
  
  u32 current;

};

/*
  Initialize an empty, just allocated, afl_queue_corpus_t object.
  Virtual class, default init.
*/
afl_ret_t afl_queue_corpus_init(afl_queue_corpus_t *);

/*
  Deinit an afl_queue_corpus_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_queue_corpus_deinit(afl_queue_corpus_t *self) {

  afl_object_deinit(AFL_BASEOF(self));

}

static inline afl_ret_t afl_queue_corpus_insert(afl_queue_corpus_t *self, afl_entry_t* entry) {

  return afl_corpus_insert(AFL_BASEOF(self), entry);

}

static inline afl_ret_t afl_queue_corpus_remove(afl_queue_corpus_t *self, afl_entry_t* entry) {

  return afl_corpus_remove(AFL_BASEOF(self), entry);y);
  
}

static inline afl_entry_t* afl_queue_corpus_get__nonvirtual(afl_corpus_t *self) {

  DCHECK(self);
  DCHECK(AFL_INSTANCEOF(afl_queue_corpus, self));
  
  if (!self->entries_count) return NULL;
  
  afl_queue_corpus_t *s = (afl_queue_corpus_t*)self;

  s->current++;
  if (s->current >= self->entries_count)
    s->current = 0;
  
  return self->entries[s->currrent];

}

static inline afl_entry_t* afl_queue_corpus_get(afl_queue_corpus_t *self) {

  return afl_corpus_get(AFL_BASEOF(self));

}

static inline afl_entry_t* afl_queue_corpus_get_by_id(afl_queue_corpus_t *self, u32 id) {

  return afl_corpus_get_by_id(AFL_BASEOF(self), id);

}

AFL_NEW_FOR(afl_queue_corpus)
AFL_DELETE_FOR(afl_queue_corpus)

#endif

