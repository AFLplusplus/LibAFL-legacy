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
#include <sys/stat.h>
#include <unistd.h>
#include "libinput.h"
#include "afl-errors.h"

void _afl_input_init_(raw_input_t *input) {

  input->funcs.clear = raw_inp_clear_default;
  input->funcs.copy = raw_inp_copy_default;
  input->funcs.deserialize = raw_inp_deserialize_default;
  input->funcs.empty = raw_inp_empty_default;
  input->funcs.get_bytes = raw_inp_get_bytes_default;
  input->funcs.load_from_file = raw_inp_load_from_file_default;
  input->funcs.restore = raw_inp_restore_default;
  input->funcs.save_to_file = raw_inp_save_to_file_default;
  input->funcs.serialize = raw_inp_serialize_default;

}

// default implemenatations for the vtable functions for the raw_input type

u8 raw_inp_clear_default(raw_input_t *input) {

  void *s = memset(input->bytes, 0x0, input->len);

  if (s != (void *)input) return INPUT_CLEAR_FAIL;

  return ALL_OK;

}

raw_input_t *raw_inp_copy_default(raw_input_t *orig_inp) {

  raw_input_t *copy_inp = afl_input_init(NULL);
  copy_inp->bytes = ck_alloc(orig_inp->len);
  memcpy(copy_inp->bytes, orig_inp->bytes, orig_inp->len);
  return copy_inp;

}

u8 raw_inp_deserialize_default(raw_input_t *input, u8 *bytes, size_t len) {

  ck_free(input->bytes);
  input->bytes = bytes;
  input->len = len;

  return ALL_OK;

}

u8 *raw_inp_get_bytes_default(raw_input_t *input) {

  return input->bytes;

}

u8 raw_inp_load_from_file_default(raw_input_t *input, u8 *fname) {


  struct stat st;
  s32         fd = open((char *)fname, O_RDONLY);

  if (fd < 0) { return AFL_ERROR_FILE_OPEN; }

  if (fstat(fd, &st) || !st.st_size) {

    return AFL_ERROR_FILE_SIZE;

  }

  input->len = st.st_size;
  input->bytes = malloc(input->len);

  int ret = read(fd, input->bytes, input->len);

  if (ret != input->len)  { return AFL_ERROR_SHORT_READ; }

  close(fd);

  return 0;

}

u8 raw_inp_save_to_file_default(raw_input_t *input, u8 *fname) {

  FILE *f = fopen((char *)fname, "w+");

  if (!f) return FILE_OPEN_ERROR;

  fwrite(input->bytes, 1, input->len, f);

  fclose(f);
  return ALL_OK;

}

u8 raw_inp_restore_default(raw_input_t *input, raw_input_t *new_inp) {

  ck_free(input->bytes);
  input->bytes = new_inp->bytes;

  return ALL_OK;

}

raw_input_t *raw_inp_empty_default(raw_input_t *input) {

  /* TODO: Implementation */
  return NULL;

}

u8 *raw_inp_serialize_default(raw_input_t *input) {

  /* TODO: Implementation */
  return NULL;

}

