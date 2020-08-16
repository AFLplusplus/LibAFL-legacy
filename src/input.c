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
#include <sys/types.h>
#include <unistd.h>

#include "input.h"
#include "afl-returns.h"

afl_ret_t afl_input_init(raw_input_t *input) {

  input->funcs.clear = raw_inp_clear_default;
  input->funcs.copy = raw_inp_copy_default;
  input->funcs.deserialize = raw_inp_deserialize_default;
  input->funcs.get_bytes = raw_inp_get_bytes_default;
  input->funcs.load_from_file = raw_inp_load_from_file_default;
  input->funcs.restore = raw_inp_restore_default;
  input->funcs.save_to_file = raw_inp_save_to_file_default;
  input->funcs.serialize = raw_inp_serialize_default;

  input->bytes = 0x0;
  input->len = 0x0;

  return AFL_RET_SUCCESS;

}

void afl_input_deinit(raw_input_t *input) {

  if (input->bytes) { free(input->bytes); }

  input->bytes = NULL;
  input->len = 0;

  return;

}

// default implemenatations for the vtable functions for the raw_input type

void raw_inp_clear_default(raw_input_t *input) {

  memset(input->bytes, 0x0, input->len);
  input->len = 0;

  return;

}

raw_input_t *raw_inp_copy_default(raw_input_t *orig_inp) {

  raw_input_t *copy_inp = afl_input_create();
  if (!copy_inp) { return NULL; }
  copy_inp->bytes = calloc(orig_inp->len + 1, sizeof(u8));
  if (!copy_inp->bytes) {

    afl_input_delete(copy_inp);
    return NULL;

  }

  memcpy(copy_inp->bytes, orig_inp->bytes, orig_inp->len);
  copy_inp->len = orig_inp->len;
  return copy_inp;

}

void raw_inp_deserialize_default(raw_input_t *input, u8 *bytes, size_t len) {

  if (input->bytes) free(input->bytes);
  input->bytes = bytes;
  input->len = len;

  return;

}

u8 *raw_inp_get_bytes_default(raw_input_t *input) {

  return input->bytes;

}

afl_ret_t raw_inp_load_from_file_default(raw_input_t *input, char *fname) {

  struct stat st;
  s32         fd = open(fname, O_RDONLY);

  if (fd < 0) { return AFL_RET_FILE_OPEN_ERROR; }

  if (fstat(fd, &st) || !st.st_size) { return AFL_RET_FILE_SIZE; }

  input->len = st.st_size;
  input->bytes = calloc(input->len + 1, 1);
  if (!input->bytes) { return AFL_RET_ALLOC; }

  ssize_t ret = read(fd, input->bytes, input->len);
  close(fd);

  if (ret < 0 || (size_t)ret != input->len) { return AFL_RET_SHORT_READ; }

  return AFL_RET_SUCCESS;

}

afl_ret_t raw_inp_save_to_file_default(raw_input_t *input, char *fname) {

  s32 fd = open(fname, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (fd < 0) { return AFL_RET_FILE_OPEN_ERROR; }

  ssize_t write_len = write(fd, input->bytes, input->len);

  if (write_len < (ssize_t)input->len) { return AFL_RET_SHORT_WRITE; }

  close(fd);

  return AFL_RET_SUCCESS;

}

void raw_inp_restore_default(raw_input_t *input, raw_input_t *new_inp) {

  input->bytes = new_inp->bytes;

  return;

}

u8 *raw_inp_serialize_default(raw_input_t *input) {

  // Very stripped down implementation, actually depends on user alot.
  return input->bytes;

}

