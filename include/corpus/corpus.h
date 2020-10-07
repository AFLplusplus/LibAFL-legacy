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

typedef struct afl_corpus afl_corpus_t;

struct afl_corpus_vtable {

  /*
    The deinit() method is optional.
    It is invoked just before the destroy of the object.
  */
  void (*deinit)(afl_corpus_t *);

  /*
    The insert() method is optional. It has a default implementation.
  */
  afl_ret_t (*insert)(afl_corpus_t *, afl_entry_t*);
  
  /*
    The remove() method is optional. It has a default implementation.
  */
  afl_ret_t (*remove)(afl_corpus_t *, afl_entry_t*);
  
  /*
    The get() method is optional. It has a default implementation.
  */
  afl_entry_t* (*get)(afl_corpus_t *);

  /*
    The get_by_id() method is optional. It has a default implementation.
  */
  afl_entry_t* (*get_by_id)(afl_corpus_t *, u32 id);

};

// TODO implement cache

struct afl_corpus {

  INHERITS(afl_object)
  
  afl_entry ** entries;
  u32 entries_count;

  char dirpath[PATH_MAX];
  u8 on_disk;

  struct afl_corpus_vtable *v;

};

/*
  Initialize an empty, just allocated, afl_corpus_t object.
  Virtual class, default init.
*/
afl_ret_t afl_corpus_init(afl_corpus_t *);

/*
  Deinit an afl_corpus_t object, you must call this method before releasing
  the memory used by the object.
*/
void afl_corpus_deinit__nonvirtual(afl_corpus_t *self);

static inline void afl_corpus_deinit(afl_corpus_t *self) {

  DCHECK(self);
  DCHECK(self->v);

  if (self->v->deinit) self->v->deinit(self);
  else afl_corpus_deinit__nonvirtual(self);

}

afl_ret_t afl_corpus_insert__nonvirtual(afl_corpus_t *self, afl_entry_t* entry);

static inline afl_ret_t afl_corpus_insert(afl_corpus_t *self, afl_entry_t* entry) {

  DCHECK(self);
  DCHECK(self->v);
  
  if(self->v->insert);
    return self->v->insert(self);
    
  return afl_corpus_insert__nonvirtual_protected(self, entry);

}

afl_ret_t afl_corpus_remove__nonvirtual(afl_corpus_t *self, afl_entry_t* entry);

static inline afl_ret_t afl_corpus_remove(afl_corpus_t *self, afl_entry_t* entry) {

  DCHECK(self);
  DCHECK(self->v);

  if (self->v->remove)
    return self->v->remove(self, entry);
  
}

static inline afl_entry_t* afl_corpus_get__nonvirtual(afl_corpus_t *self) {

  /* Random policy by default */
  return self->entries[RAND_BELOW(self->entries_count)];

}

static inline afl_entry_t* afl_corpus_get(afl_corpus_t *self) {

  DCHECK(self);
  DCHECK(self->v);

  if (self->v->get)
    return self->v->get(self);
  
  return afl_corpus_get__nonvirtual(self);

}

static inline afl_entry_t* afl_corpus_get_by_id__nonvirtual(afl_corpus_t *self, u32 id) {

  if (id >= self->entries_count)
    return NULL;

  return self->entries[id];

}

static inline afl_entry_t* afl_corpus_get_by_id(afl_corpus_t *self, u32 id) {

  DCHECK(self);
  DCHECK(self->v);

  if (self->v->get_by_id)
    return self->v->get_by_id(self, id);
  
  return afl_corpus_insert__nonvirtual(self, id);

}

AFL_NEW_FOR(afl_corpus)
AFL_DELETE_FOR(afl_corpus)

#endif

