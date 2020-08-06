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

#ifndef INPUT_FILE_INCLUDED
#define INPUT_FILE_INCLUDED

#include "libcommon.h"
#include "afl-returns.h"

#define DEFAULT_INPUT_LEN 100

typedef struct raw_input raw_input_t;

struct raw_input_functions {

  afl_ret_t (*deserialize)(raw_input_t *, u8 *, size_t);
  u8 *(*serialize)(raw_input_t *);
  raw_input_t *(*copy)(raw_input_t *);
  raw_input_t *(*empty)(raw_input_t *);
  afl_ret_t (*restore)(raw_input_t *, raw_input_t *);
  afl_ret_t (*load_from_file)(raw_input_t *, char *);
  afl_ret_t (*save_to_file)(raw_input_t *, char *);
  afl_ret_t (*clear)(raw_input_t *);
  u8 *(*get_bytes)(raw_input_t *);

};

struct raw_input {

  u8 *   bytes;  // Raw input bytes
  size_t len;  // Length of the input field. C++ had strings, we have to make do
               // with storing the lengths :/

  struct raw_input_functions funcs;

};

void _afl_input_init_(raw_input_t *);
void afl_input_deinit(raw_input_t *);

// Default implementations of the functions for raw input vtable
afl_ret_t           raw_inp_deserialize_default(raw_input_t *, u8 *, size_t);
u8 *         raw_inp_serialize_default(raw_input_t *);
raw_input_t *raw_inp_copy_default(raw_input_t *);
raw_input_t *raw_inp_empty_default(raw_input_t *);
afl_ret_t           raw_inp_restore_default(raw_input_t *, raw_input_t *);
afl_ret_t    raw_inp_load_from_file_default(raw_input_t *input, char *fname);
afl_ret_t           raw_inp_save_to_file_default(raw_input_t *, char *);
afl_ret_t           raw_inp_clear_default(raw_input_t *);
u8 *         raw_inp_get_bytes_default(raw_input_t *);

// input_clear and empty functions... difference??
// serializing and deserializing would be done on the basis of some structure
// right??

static inline raw_input_t *afl_input_init(raw_input_t *input) {

  raw_input_t *new_input = input;

  if (input) {

    _afl_input_init_(input);

  }

  else {

    new_input = calloc(1, sizeof(raw_input_t));
    if (!new_input) return NULL;

    _afl_input_init_(new_input);

  }

  return new_input;

}

#define AFL_INPUT_DEINIT(input) afl_input_deinit(input);

#endif

