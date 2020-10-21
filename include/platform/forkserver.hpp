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

#include "errors.hpp"
#include "result.hpp"

// TODO this is an hack atm
#ifndef PLATFORM
#define PLATFORM posix
#endif

namespace afl {

class ChildExecutionError : public OSError {
 public:
  using OSError::OSError;
};

class ChildBrokenError : public Error {
 public:
  ChildBrokenError(const char* src_file, size_t src_line)
      : Error(src_file, src_line) {}

  const std::string Message() override { return "Broken child"; }
};

class ForkServerExecutor;

class ForkServerHelper {
#if PLATFORM == posix

  int pid;
  int outFd;
  int devNullFd;
  int ctlFd, stFd;

  s32 childStatus;
  u8 lastKillSignal;

  u32* messagePtr;

  char* outFileName;

#endif

  bool lastRunTimedOut;

 public:
  ForkServerHelper();

  Result<void> Start(ForkServerExecutor* executor, char** argv);

  Result<void> WriteInput(ForkServerExecutor* executor,
                          u8* buffer,
                          size_t size);

  Result<ExitType> ExecuteOnce(ForkServerExecutor* executor);
};

}  // namespace afl
