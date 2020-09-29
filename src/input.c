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
#include "xxh3.h"
#include "xxhash.h"
#include "alloc-inl.h"

afl_ret_t afl_input_init(afl_input_t *input) {

  input->funcs.clear = afl_input_clear;
  input->funcs.copy = afl_input_copy;
  input->funcs.deserialize = afl_input_deserialize;
  input->funcs.get_bytes = afl_input_get_bytes;
  input->funcs.load_from_file = afl_input_load_from_file;
  input->funcs.restore = afl_input_restore;
  input->funcs.save_to_file = afl_input_write_to_file;
  input->funcs.serialize = afl_input_serialize;
  input->funcs.delete = afl_input_delete;

  input->copy_buf = NULL;

  input->bytes = NULL;
  input->len = 0;

  return AFL_RET_SUCCESS;

}

void afl_input_deinit(afl_input_t *input) {

  /* Deiniting requires a little hack. We free the byte ONLY if copy buf is not NULL. Because then we can assume that the input is in the queue*/
  if (input->bytes && input->copy_buf) { 
    free(input->bytes);
    afl_free(input->copy_buf);
  }

  input->bytes = NULL;
  input->len = 0;

  return;

}

// default implemenatations for the vtable functions for the raw_input type

void afl_input_clear(afl_input_t *input) {

  memset(input->bytes, 0x0, input->len);
  input->len = 0;

  return;

}

afl_input_t *afl_input_copy(afl_input_t *orig_inp) {

  afl_input_t *copy_inp = afl_input_new();
  if (!copy_inp) { return NULL; }
  copy_inp->bytes = afl_realloc(orig_inp->copy_buf, (orig_inp->len) * sizeof(u8));
  orig_inp->copy_buf = copy_inp->bytes;
  if (!copy_inp->bytes) {

    afl_input_delete(copy_inp);
    return NULL;

  }

  memcpy(copy_inp->bytes, orig_inp->bytes, orig_inp->len);
  copy_inp->len = orig_inp->len;
  return copy_inp;

}

void afl_input_deserialize(afl_input_t *input, u8 *bytes, size_t len) {

  if (input->bytes) free(input->bytes);
  input->bytes = bytes;
  input->len = len;

  return;

}

u8 *afl_input_get_bytes(afl_input_t *input) {

  return input->bytes;

}

afl_ret_t afl_input_load_from_file(afl_input_t *input, char *fname) {

  struct stat st;
  s32         fd = open(fname, O_RDONLY);

  if (fd < 0) { return AFL_RET_FILE_OPEN_ERROR; }

  if (fstat(fd, &st) || !st.st_size) {

    close(fd);
    return AFL_RET_FILE_SIZE;

  }

  input->len = st.st_size;
  input->bytes = calloc(input->len + 1, 1);
  if (!input->bytes) {

    close(fd);
    return AFL_RET_ALLOC;

  }

  ssize_t ret = read(fd, input->bytes, input->len);
  close(fd);

  if (ret < 0 || (size_t)ret != input->len) {

    free(input->bytes);
    input->bytes = NULL;
    return AFL_RET_SHORT_READ;

  }

  return AFL_RET_SUCCESS;

}

afl_ret_t afl_input_write_to_file(afl_input_t *input, char *fname) {

  // if it already exists we will not overwrite it
  if (access(fname, W_OK) == 0) return AFL_RET_FILE_DUPLICATE;

  s32 fd = open(fname, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (fd < 0) { return AFL_RET_FILE_OPEN_ERROR; }

  ssize_t write_len = write(fd, input->bytes, input->len);
  close(fd);

  if (write_len < (ssize_t)input->len) { return AFL_RET_SHORT_WRITE; }

  return AFL_RET_SUCCESS;

}

void afl_input_restore(afl_input_t *input, afl_input_t *new_inp) {

  input->bytes = new_inp->bytes;

  return;

}

u8 *afl_input_serialize(afl_input_t *input) {

  // Very stripped down implementation, actually depends on user alot.
  return input->bytes;

}

afl_ret_t afl_input_dump_to_file(char *filetag, afl_input_t *data, char *directory) {

  char filename[PATH_MAX];

  /* TODO: This filename should be replaced by "crashes-SHA_OF_BYTES" later */

  u64 input_data_checksum = XXH64(data->bytes, data->len, HASH_CONST);
  if (directory) {

    snprintf(filename, sizeof(filename), "%s/%s-%016llx", directory, filetag, input_data_checksum);

  } else {

    snprintf(filename, sizeof(filename), "%s-%016llx", filetag, input_data_checksum);

  }

  return afl_input_write_to_file(data, filename);

}

// Timeout related functions
afl_ret_t afl_input_dump_to_timeoutfile(afl_input_t *data, char *directory) {

  return afl_input_dump_to_file("timeout", data, directory);

}

// Crash related functions
afl_ret_t afl_input_dump_to_crashfile(afl_input_t *data, char *directory) {

  return afl_input_dump_to_file("crash", data, directory);

}

