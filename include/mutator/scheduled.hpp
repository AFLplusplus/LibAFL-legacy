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

#ifndef LIBAFL_MUTATOR_SCHEDULED_H
#define LIBAFL_MUTATOR_SCHEDULED_H

#include "mutator/mutator.hpp"
#include "utils/random.hpp"

#include <vector>

namespace afl {

class ScheduledMutator;

typedef void (*MutationFunctionType)(ScheduledMutator*, Input*);

class ScheduledMutator : public Mutator {

  std::vector<MutationFunctionType> mutations;

public:

  using Mutator::Mutator;

  virtual size_t Iterations(Input* input) {
    return 1 << (1 + (size_t)GetRandomState()->Below(7));
  }
  
  virtual MutationFunctionType Schedule(Input* input) {
    return GetMutationByIndex(GetRandomState()->Below(GetMutationsCount()));
  }

  MutationFunctionType GetMutationByIndex(size_t index) {
    if (index >= mutations.size())
      return nullptr;
    return mutations[index];
  }

  size_t GetMutationsCount() {
    return mutations.size();
  }
  
  void AddMutation(MutationFunctionType mutation) {
    mutations.push_back(mutation);
  }
  
  /*
    Mutate an Input in-place.
  */
  inline void Mutate(Input* input, size_t stage_idx) override {
  
    (void)stage_idx;
  
    size_t num = Iterations(input);
    
    for (size_t i = 0; i < num; ++i)
      Schedule(input)(this, input);

  }

};

} // namespace afl

#endif

