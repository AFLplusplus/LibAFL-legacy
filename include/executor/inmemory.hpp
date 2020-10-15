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

#ifndef LIBAFL_EXECUTOR_INMEMORY_H
#define LIBAFL_EXECUTOR_INMEMORY_H

#include "result.hpp"
#include "executor/executor.hpp"

namespace afl {

typedef ExitType (*HarnessFunction)(Executor *, u8 *, size_t);

/*
  An Executor is an entity with a set of violation oracles, a set of observation channels, a function that allows
  instructing the SUT about the input to test, and a function to run the SUT.
*/
class InMemoryExecutor : public Executor {

protected:

  HarnessFunction harnessFunction;
  
  /* libFuzzer compatibility */
  char **argv;
  int    argc;

public:

  InMemoryExecutor(HarnessFunction harness_function) : harnessFunction(harness_function) {}

  virtual Result<ExitType> RunTarget() override;

};

} // namespace afl

#endif
