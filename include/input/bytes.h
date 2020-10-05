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

#ifndef LIBAFL_INPUT_BYTES_H
#define LIBAFL_INPUT_BYTES_H

#include "object.h"
#include "error.h"

#include "input/input.h"

extern struct afl_input_vtable afl_bytes_input_vtable_instance;

typedef struct afl_bytes_input afl_bytes_input_t;

struct afl_bytes_input {

  INHERITS(afl_input)

  u8 *   bytes;
  size_t size;

};

/*
  Initialize an empty, just allocated, afl_bytes_input_t object. Default is an empty buffer.
*/
afl_ret_t afl_bytes_input_init(afl_bytes_input_t *self);

/*
  Deserialize the input from a bytes array.
*/
afl_ret_t afl_bytes_input_deserialize(afl_input_t *self, u8 *buffer, size_t size);

/*
  Serialize the input to a bytes array.
  If *size_out is already set and the real size does not fit, return an error.
*/
afl_ret_t afl_bytes_input_serialize(afl_input_t *self, u8 **buffer_out, size_t *size_out);

/*
  Copy the input.
*/
afl_input_t *afl_bytes_input_copy(afl_input_t *self);

/*
  Clear the input.
*/
static inline void afl_bytes_input_clear(afl_input_t *self) {

  DCHECK(self);
  DCHECK(INSTANCE_OF(afl_bytes_input, self));

  afl_bytes_input_t *b = (afl_bytes_input_t *)self;
  b->bytes = NULL;
  b->size = 0;

}

/*
  Destroy the context of an afl_bytes_input_t.
*/
static inline void afl_bytes_input_deinit(afl_executor_t *self) {

  afl_input_deinit(self);

}

AFL_NEW_FOR(afl_bytes_input)
AFL_DELETE_FOR(afl_bytes_input)

#endif

