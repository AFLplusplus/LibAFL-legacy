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

#pragma once

#include "result.hpp"
#include "types.hpp"

// TODO this is an hack atm
#ifndef PLATFORM
#define PLATFORM posix
#endif

namespace afl {

const size_t kSharedMemoryNameMaxSize = 24;

class SharedMemory {
  char name[kSharedMemoryNameMaxSize];

#if PLATFORM == posix
  int fd;
#endif

  u8* mem = nullptr;
  size_t size = 0;

 public:
  SharedMemory() {}
  ~SharedMemory();

  Result<void> ByName(const char* name, size_t size);

  Result<void> Create(size_t size);

  Result<bool> SetEnv(const char* env_name);

  bool IsInited() { return mem != nullptr; }

  u8* GetMem() { return mem; }

  size_t GetSize() { return size; }

  const char* GetName() { return name; }
};

}  // namespace afl
