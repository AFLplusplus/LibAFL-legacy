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

#include "libcommon.h"
#include "afl-returns.h"

#define DEFAULT_INPUT_LEN 100

typedef struct raw_input raw_input_t;

struct raw_input_functions {

  void (*deserialize)(raw_input_t *this_input, u8 *bytes, size_t len);
  u8 *(*serialize)(raw_input_t *this_input);
  raw_input_t *(*copy)(raw_input_t *this_input);
  void (*restore)(raw_input_t *this_input, raw_input_t *input);
  afl_ret_t (*load_from_file)(raw_input_t *this_input, char *fname);
  afl_ret_t (*save_to_file)(raw_input_t *this_input, char *fname);
  void (*clear)(raw_input_t *this_input);
  u8 *(*get_bytes)(raw_input_t *this_input);

};

struct raw_input {

  u8 *   bytes;  // Raw input bytes
  size_t len;  // Length of the input field. C++ had strings, we have to make do
               // with storing the lengths :/

  struct raw_input_functions funcs;

};

afl_ret_t afl_input_init(raw_input_t *input);
void      afl_input_deinit(raw_input_t *input);

// Default implementations of the functions for raw input vtable

void         raw_inp_deserialize_default(raw_input_t *this_input, u8 *bytes,
                                         size_t len);
u8 *         raw_inp_serialize_default(raw_input_t *this_input);
raw_input_t *raw_inp_copy_default(raw_input_t *this_input);
void      raw_inp_restore_default(raw_input_t *this_input, raw_input_t *input);
afl_ret_t raw_inp_load_from_file_default(raw_input_t *this_inputinput,
                                         char *       fname);
afl_ret_t raw_inp_save_to_file_default(raw_input_t *this_input, char *fname);
void      raw_inp_clear_default(raw_input_t *this_input);
u8 *      raw_inp_get_bytes_default(raw_input_t *this_input);

/* Function to create and destroy a new input, allocates memory and initializes
  it. In destroy, it first deinitializes the struct and then frees it. */

static inline raw_input_t *afl_input_create() {

  raw_input_t *input = calloc(1, sizeof(raw_input_t));
  if (!input) { return NULL; }

  if (afl_input_init(input) != AFL_RET_SUCCESS) { return NULL; }

  return input;

}

static inline void afl_input_delete(raw_input_t *input) {

  afl_input_deinit(input);
  free(input);

}

#endif

