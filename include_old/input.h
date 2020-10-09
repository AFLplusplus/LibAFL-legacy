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

#ifndef LIBINPUT_H
#define LIBINPUT_H

#include "common.h"
#include "afl-returns.h"

typedef struct afl_input afl_input_t;

struct afl_input_funcs {

  void (*deserialize)(afl_input_t *this_input, u8 *bytes, size_t len);
  u8 *(*serialize)(afl_input_t *this_input);
  afl_input_t *(*copy)(afl_input_t *this_input);
  void (*restore)(afl_input_t *this_input, afl_input_t *input);
  afl_ret_t (*load_from_file)(afl_input_t *this_input, char *fname);
  afl_ret_t (*save_to_file)(afl_input_t *this_input, char *fname);
  void (*clear)(afl_input_t *this_input);
  u8 *(*get_bytes)(afl_input_t *this_input);

  void (*delete)(afl_input_t *this_input);

};

struct afl_input {

  u8 *   bytes;  // Raw input bytes
  size_t len;    // Length of the input

  u8 *copy_buf;

  struct afl_input_funcs funcs;

};

afl_ret_t afl_input_init(afl_input_t *input);
void      afl_input_deinit(afl_input_t *input);

// Default implementations of the functions for raw input vtable

void         afl_input_deserialize(afl_input_t *this_input, u8 *bytes, size_t len);
u8 *         afl_input_serialize(afl_input_t *this_input);
afl_input_t *afl_input_copy(afl_input_t *this_input);
void         afl_input_restore(afl_input_t *this_input, afl_input_t *input);
afl_ret_t    afl_input_load_from_file(afl_input_t *this_inputinput, char *fname);
afl_ret_t    afl_input_write_to_file(afl_input_t *this_input, char *fname);
void         afl_input_clear(afl_input_t *this_input);
u8 *         afl_input_get_bytes(afl_input_t *this_input);

/* Write the contents of the input to a file at the given loc */
afl_ret_t afl_input_write_to_file(afl_input_t *data, char *filename);

/* Write the contents of the input to a timeoutfile */
afl_ret_t afl_input_dump_to_timeoutfile(afl_input_t *data, char *);

/* Write the contents of the input which causes a crash in the target to a crashfile */
afl_ret_t afl_input_dump_to_crashfile(afl_input_t *, char *);

/* Function to create and destroy a new input, allocates memory and initializes
  it. In destroy, it first deinitializes the struct and then frees it. */

AFL_NEW_AND_DELETE_FOR(afl_input);

#endif

