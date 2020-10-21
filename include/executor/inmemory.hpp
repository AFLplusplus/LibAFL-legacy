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

#include "executor/executor.hpp"
#include "input/input.hpp"

namespace afl {

typedef ExitType (*HarnessFunction)(Executor*, u8*, size_t);

class InMemoryExecutor : public Executor {
 protected:
  HarnessFunction harnessFunction;

  /* libFuzzer compatibility */
  char** argv;
  int argc;

  u8* buffer;

  static InMemoryExecutor* currentInstance;

 public:
  InMemoryExecutor(HarnessFunction harness_function)
      : harnessFunction(harness_function) {
    buffer = new u8[kMaxInputBytes];
  }

  virtual Result<ExitType> RunTarget() override {
    auto res = GetCurrentInput()->Serialize(buffer, kMaxInputBytes);
    if (res.IsOk()) {
      currentInstance = this;
      auto exit_type = harnessFunction(this, buffer, res.Unwrap());
      currentInstance = nullptr;
      return exit_type;
    }
    return ExitType::kOk;
  }
  
  static InMemoryExecutor* Current() {
    return currentInstance;
  }
};

}  // namespace afl
