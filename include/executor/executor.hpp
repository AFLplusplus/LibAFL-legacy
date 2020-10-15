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

#ifndef LIBAFL_EXECUTOR_EXECUTOR_H
#define LIBAFL_EXECUTOR_EXECUTOR_H

#include <vector>

#include "result.hpp"

namespace afl {

class ObservationChannel;
class Input;

/*
  An Executor is an entity with a set of violation oracles, a set of observation channels, a function that allows
  instructing the SUT about the input to test, and a function to run the SUT.
*/
class Executor {

protected:

  std::vector<ObservationChannel*> observationChannels;
  
  Input* currentInput;
  
public:

  /*
    Run the target represented by the executor.
  */
  virtual Result<ExitType> RunTarget() = 0;
  
  /*
    Instruct the SUT about the input.
  */
  virtual void PlaceInput(Input* input) {
    currentInput = input;
  }
  
  inline Input* CurrentInput() {
    return currentInput;
  }
  
  inline std::vector<ObservationChannel*>& ObservationChannels() {
    return observationChannels;
  }
  
  inline void AddObserationChannel(ObservationChannel* observation_channel) {
    observationChannels.push_back(observation_channel);
  }

};

} // namespace afl

#endif
