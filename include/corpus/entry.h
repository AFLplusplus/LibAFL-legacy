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

#ifndef LIBAFL_CORPUS_ENTRY_H
#define LIBAFL_CORPUS_ENTRY_H

#include "object.h"
#include "error.h"
#include "rand.h"

#include "corpus/meta.h"

typedef struct afl_entry afl_entry_t;

extern struct afl_object_vtable afl_entry_vtable_instance;

struct afl_entry {

  AFL_INHERITS(afl_object)
  
  afl_input* input;
  
  afl_entry_metadata_t** meta;
  u32 meta_count;
  
  char* filename;
  u8 ondisk;

};

/*
  Initialize an empty, just allocated, afl_entry_t object.
*/
afl_ret_t afl_entry_init(afl_entry_t *, afl_input*);

/* Get a metadata object by typeinfo. */
afl_entry_metadata_t* afl_entry_get_meta(afl_entry_t*, afl_typeinfo_t);

/* Set metadata. */
afl_entry_set_meta(afl_entry_t*, afl_entry_metadata_t*);

/*
  Deinit an afl_entry_t object, you must call this method before releasing
  the memory used by the object.
*/
void afl_entry_deinit__nonvirtual(afl_object_t *self);

static inline void afl_entry_deinit(afl_entry_t *self) {

  afl_object_deinit(AFL_BASEOF(self));

}

afl_input* afl_entry_load_input(afl_entry_t *);

AFL_NEW_FOR_WITH_PARAMS(afl_entry, AFL_DECL_PARAMS(afl_input* input), AFL_CALL_PARAMS(input))
AFL_DELETE_FOR(afl_entry)

#endif

