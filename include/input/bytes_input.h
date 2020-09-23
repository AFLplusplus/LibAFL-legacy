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

#include "common.h"
#include "returns.h"

typedef struct afl_bytes_input afl_bytes_input_t;

struct afl_bytes_input {

  INHERITS(afl_input)
  
  u8 *bytes;
  size_t len;

};

afl_ret_t afl_bytes_input_init(afl_bytes_input *self);

void afl_bytes_input_deinit(afl_input_t *self);

void afl_bytes_input_deserialize(afl_input_t *self, u8 *bytes, size_t len);

u8 * afl_bytes_input_serialize(afl_input_t *self);

afl_input_t * afl_bytes_input_copy(afl_input_t *self);

void afl_bytes_input_restore(afl_input_t *self, afl_input_t *input);

afl_ret_t afl_bytes_input_load_from_file(afl_input_t *self, char *fname);

afl_ret_t afl_bytes_input_write_to_file(afl_input_t *self, char *fname);

void afl_bytes_input_clear(afl_input_t *self);

u8 * afl_bytes_input_get_bytes(afl_input_t *self);

/* Write the contents of the input to a file at the given loc */
afl_ret_t afl_input_write_to_file(afl_input_t *self, char *filename);

/* Write the contents of the input to a timeoutfile */
afl_ret_t afl_input_dump_to_timeoutfile(afl_input_t *self);

/* Write the contents of the input which causes a crash in the target to a crashfile */
afl_ret_t afl_input_dump_to_crashfile(afl_input_t * self);

AFL_NEW_AND_DELETE_FOR(afl_bytes_input)

#endif
