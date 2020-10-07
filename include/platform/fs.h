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

#ifndef LIBAFL_PLATFORM_FS_H
#define LIBAFL_PLATFORM_FS_H

#include "types.h"

/// Files

enum {
  AFL_PERM_R,
  AFL_PERM_W,
  AFL_PERM_x
};

typedef struct afl_file afl_file_t;

afl_file_t* afl_file_open(char* filename, s32 permissions);

size_t afl_file_read(afl_file_t* file, u8* buf, size_t size);

size_t afl_file_write(afl_file_t* file, u8* buf, size_t size);

void afl_file_flush(afl_file_t* file);

void afl_file_close(afl_file_t* file);

/// Dirs

u8 afl_dir_exists(char* dirname);

#endif
