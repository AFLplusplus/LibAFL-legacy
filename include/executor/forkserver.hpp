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

#ifndef LIBAFL_EXECUTOR_FORKSERVER_H
#define LIBAFL_EXECUTOR_FORKSERVER_H

#include "result.hpp"

#include "executor/executor.hpp"
#include "input/input.hpp"
#include "platform/forkserver.hpp"

namespace afl {

class ForkServerExecutor : public Executor {
 public:
  enum class InputType {
    kStdin,
    kFile,
    kInMemory
  };

  ForkServerExecutor(char** argv_, InputType input_type, u32 timeout_ms) : argv(argv_), inputType(input_type), timeoutMs(timeout_ms) {
    buffer = new u8[kMaxInputBytes];
    helper.Start(this, argv).Expect("Cannot start the ForkServer");
  }
  ForkServerExecutor(char** argv_, InputType input_type) : ForkServerExecutor(argv_, input_type, 0) {}
  
  virtual Result<void> PlaceInput(Input* input) override {
    TRY(Executor::PlaceInput(input));
    size_t size = TRY(GetCurrentInput()->Serialize(buffer, kMaxInputBytes));
    return helper.WriteInput(this, buffer, size);
  }

  virtual Result<ExitType> RunTarget() override {
    helper.ExecuteOnce(this);
    return ExitType::kOk;
  }
  
  InputType GetInputType() {
    return inputType;
  }
 
  u32 GetTimeoutMs() {
    return timeoutMs;
  }
 
protected:
  ForkServerHelper helper;

  char** argv;
  InputType inputType;
  u32 timeoutMs;
  
  u8* buffer;
};

}  // namespace afl

#endif
