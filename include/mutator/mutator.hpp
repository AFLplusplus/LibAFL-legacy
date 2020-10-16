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

#ifndef LIBAFL_MUTATOR_MUTATOR_H
#define LIBAFL_MUTATOR_MUTATOR_H

#include "result.hpp"

namespace afl {

/*
  A Mutator is an entity that takes one or more inputs and generates a new derived one.
*/
class Mutator {
  
  RandomState* randomState;

public:

  Mutator(RandomState* random_state) : randomState(random_state) {}

  inline RandomState* GetRandomState() {
    return randomState;
  }
  
  inline RandomState* SetRandomState(RandomState* random_state) {
    randomState = random_state;
  }

  /*
    Mutate an Input in-place.
  */
  virtual void Mutate(Input* input, size_t stage_idx) = 0;

  inline void Mutate(Input* input) {
    Mutate(input, static_cast<size_t>(-1));
  }
  
  virtual void PostExec(bool is_interesting, size_t stage_idx) {};
  
  inline void PostExec(bool is_interesting) {
    PostExec(is_interesting, static_cast<size_t>(-1));
  }

};

} // namespace afl

#endif

