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

#ifndef LIBAFL_PLATFORM_SHMEM_H
#define LIBAFL_PLATFORM_SHMEM_H

#include "debug.hpp"
#include "errors.hpp"
#include "types.hpp"

namespace afl {

const size_t kSharedMemoryNameMaxSize = 24;

class SharedMemory {
  char name[kSharedMemoryNameMaxSize];
  void* data;

  u8* mem;
  size_t size;

 public:
  SharedMemory* ByName(const char* name);

  bool SetEnv();
};

}  // namespace afl

#endif