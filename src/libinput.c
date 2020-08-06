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
#include "afl-returns.h"

#define UNUSED(x) (void)(x)

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

void afl_input_deinit(raw_input_t *input) {

  if (input->bytes) { free(input->bytes); }

  free(input);

}

// default implemenatations for the vtable functions for the raw_input type

afl_ret_t raw_inp_clear_default(raw_input_t *input) {

  memset(input->bytes, 0x0, input->len);

  return AFL_RET_SUCCESS;

}

raw_input_t *raw_inp_copy_default(raw_input_t *orig_inp) {

  raw_input_t *copy_inp = afl_input_init(NULL);
  if (!copy_inp) { return NULL; }
  copy_inp->bytes = calloc(orig_inp->len, sizeof(u8));
  if (!copy_inp->bytes) {

    free(copy_inp);
    return NULL;

  }

  memcpy(copy_inp->bytes, orig_inp->bytes, orig_inp->len);
  return copy_inp;

}

afl_ret_t raw_inp_deserialize_default(raw_input_t *input, u8 *bytes,
                                      size_t len) {

  free(input->bytes);
  input->bytes = bytes;
  input->len = len;

  return AFL_RET_SUCCESS;

}

u8 *raw_inp_get_bytes_default(raw_input_t *input) {

  return input->bytes;

}

afl_ret_t raw_inp_load_from_file_default(raw_input_t *input, char *fname) {

  struct stat st;
  s32         fd = open((char *)fname, O_RDONLY);

  if (fd < 0) { return AFL_RET_FILE_OPEN; }

  if (fstat(fd, &st) || !st.st_size) { return AFL_RET_FILE_SIZE; }

  input->len = st.st_size;
  input->bytes = malloc(input->len);
  if (!input->bytes) { return AFL_RET_ALLOC; }

  ssize_t ret = read(fd, input->bytes, input->len);
  close(fd);

  if (ret < 0 || (size_t)ret != input->len) { return AFL_RET_SHORT_READ; }

  return AFL_RET_SUCCESS;

}

afl_ret_t raw_inp_save_to_file_default(raw_input_t *input, char *fname) {

  FILE *f = fopen((char *)fname, "w+");

  if (!f) { return AFL_RET_FILE_OPEN; }

  fwrite(input->bytes, 1, input->len, f);

  fclose(f);
  return AFL_RET_SUCCESS;

}

afl_ret_t raw_inp_restore_default(raw_input_t *input, raw_input_t *new_inp) {

  free(input->bytes);
  input->bytes = new_inp->bytes;

  return AFL_RET_SUCCESS;

}

raw_input_t *raw_inp_empty_default(raw_input_t *input) {

  UNUSED(input);

  /* TODO: Implementation */
  return NULL;

}

u8 *raw_inp_serialize_default(raw_input_t *input) {

  UNUSED(input);

  /* TODO: Implementation */
  return NULL;

}

