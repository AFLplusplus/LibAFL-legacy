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

#include <fcntl.h>
#include "libinput.h"

void afl_input_init(raw_input_t * input) {


  input->functions = ck_alloc(sizeof(raw_input_functions_t));

  input->functions->clear = _raw_inp_clear_;
  input->functions->copy = _raw_inp_copy_;
  input->functions->deserialize = _raw_inp_deserialize_;
  input->functions->empty = _raw_inp_empty_;
  input->functions->get_bytes = _raw_inp_get_bytes_;
  input->functions->load_from_file = _raw_inp_load_from_file_;
  input->functions->restore = _raw_inp_restore_;
  input->functions->save_to_file = _raw_inp_save_to_file_;
  input->functions->serialize = _raw_inp_serialize_;

}

// default implemenatations for the vtable functions for the raw_input type

u8 _raw_inp_clear_(raw_input_t *input) {

  void *s = memset(input->bytes, 0x0, input->len);

  if (s != (void *)input) return INPUT_CLEAR_FAIL;

  return ALL_OK;

}

raw_input_t *_raw_inp_copy_(raw_input_t *orig_inp) {

  raw_input_t *copy_inp = AFL_INPUT_INIT(NULL);
  copy_inp->bytes = ck_alloc(orig_inp->len);
  memcpy(copy_inp->bytes, orig_inp->bytes, orig_inp->len);
  return copy_inp;

}

u8 _raw_inp_deserialize_(raw_input_t *input, u8 *bytes, size_t len) {

  ck_free(input->bytes);
  input->bytes = bytes;
  input->len = len;

  return ALL_OK;

}

u8 *_raw_inp_get_bytes_(raw_input_t *input) {

  return input->bytes;

}

u8 _raw_inp_load_from_file_(raw_input_t *input, u8 *fname) {

  if (!input->len) input->len = DEFAULT_INPUT_LEN;

  FILE *f = fopen((char *)fname, "r");
  input->bytes = ck_alloc(sizeof(input->len));

  if (!f) return FILE_OPEN_ERROR;

  int  i = 0;
  char c = '\x00';

  while (c != EOF) {

    c = fgetc(f);
    input->bytes[i] = c;

    i++;

    if (i >= input->len) {

      input->bytes = ck_realloc(input->bytes, 2 * input->len);
      input->len = input->len * 2;

    }

  }

  fclose(f);

  return ALL_OK;

}

u8 _raw_inp_save_to_file_(raw_input_t *input, u8 *fname) {

  FILE *f = fopen((char *)fname, "w+");

  if (!f) return FILE_OPEN_ERROR;

  fwrite(input->bytes, 1, input->len, f);

  fclose(f);
  return ALL_OK;

}

u8 _raw_inp_restore_(raw_input_t *input, raw_input_t *new_inp) {

  ck_free(input->bytes);
  input->bytes = new_inp->bytes;

  return ALL_OK;

}

