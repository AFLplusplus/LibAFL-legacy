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

#ifndef LIBAFL_INPUT_INPUT_H
#define LIBAFL_INPUT_INPUT_H

#include "object.h"
#include "error.h"

typedef struct afl_input afl_input_t;

struct afl_input_vtable {

  void (*destroy)(afl_input_t *);

  afl_ret_t (*deserialize)(afl_input_t *, u8 *, size_t);
  
  afl_ret_t (*serialize)(afl_input_t *, u8**, size_t*);
  
  afl_input_t *(*copy)(afl_input_t *);
  
  void (*clear)(afl_input_t *);
  
};


/*
  An Input entity defines one possible sample from the Input Space and can hold properties about the input itself, the relation between the input and the SUT, or the input and the specification.
*/
struct afl_input {

  INHERIT(afl_object)

  struct afl_input_vtable v;

};

/*
  Load and deserialize an input from file.
*/
afl_ret_t afl_input_load_from_file(afl_input_t * self, char* filename);

/*
  Serialize and save an input to a file.
*/
afl_ret_t afl_input_save_to_file(afl_input_t * self, char* filename);

/*
  Destroy an afl_input_t object, you must call this method before releasing
  the memory used by the object.
*/
static inline void afl_input_destroy(afl_executor_t * self) {
  
  DCHECK(self);
  if (self->v.destroy)
    self->v.destroy(self);

}

/*
  Deserialize the input from a bytes array.
*/
static inline afl_ret_t afl_input_deserialize(afl_input_t * self, u8* buffer, size_t size) {
  
  DCHECK(self);
  CHECK(self->v.deserialize);
  
  return self->v.deserialize(self, buffer, size);

}

/*
  Serialize the input to a bytes array.
  If *size_out is already set and the real size does not fit, return an error.
*/
static inline afl_ret_t afl_input_serialize(afl_input_t * self, u8** buffer_out, size_t* size_out) {
  
  DCHECK(self);
  CHECK(self->v.serialize);
  
  return self->v.serialize(self, buffer_out, size_out);

}

/*
  Copy the input.
*/
static inline afl_input_t* afl_input_copy(afl_input_t * self) {
  
  DCHECK(self);
  CHECK(self->v.copy);
  
  return self->v.copy(self);

}

/*
  Clear the input.
*/
static inline void afl_input_clear(afl_input_t * self) {
  
  DCHECK(self);
  CHECK(self->v.clear);
  
  self->v.clear(self);

}

AFL_DELETE_FOR(afl_input)

#endif
