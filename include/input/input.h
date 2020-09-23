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

typedef struct afl_input afl_input_t;

struct afl_input_funcs {

  void (*deserialize)(afl_input_t *self, u8 *bytes, size_t len);
  u8 *(*serialize)(afl_input_t *self);
  afl_input_t *(*copy)(afl_input_t *self);
  void (*restore)(afl_input_t *self, afl_input_t *input);
  afl_ret_t (*load_from_file)(afl_input_t *self, char *fname);
  afl_ret_t (*save_to_file)(afl_input_t *self, char *fname);
  void (*clear)(afl_input_t *self);
  u8 *(*get_bytes)(afl_input_t *self);
  void (*destroy)(afl_input_t *self);

};

// Virtual class, does not provide afl_input_init and afl_input_new

struct afl_input {

  INHERIT(afl_object)

  struct afl_input_funcs funcs;

};

#endif
