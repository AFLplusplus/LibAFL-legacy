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

#include "stage/stage.hpp"

#include <vector>

namespace afl {

class MutationalStage : public Stage {
  std::vector<Mutator*> mutators;

 public:
  using Stage::Stage;

  virtual size_t Iterations(Entry* entry) {
    (void) entry;
    return 1 + (size_t)GetRandomState()->Below(128);
  }

  Result<void> Perform(Input* input, Entry* entry) override {
    size_t num = Iterations(entry);
    auto original = TRY(entry->LoadInput());

    for (size_t i = 0; i < num; ++i) {
      for (auto mutator : mutators)
        TRY(mutator->Mutate(input, i));

      bool interesting = TRY(GetEngine()->Execute(input, entry));

      for (auto mutator : mutators)
        TRY(mutator->PostExec(interesting, i));

      TRY(input->Assign(original));
    }
    return OK();
  }

  void AddMutator(Mutator* mutator) { mutators.push_back(mutator); }

  template <class MutatorType, typename... ArgsTypes>
  MutatorType* CreateMutator(ArgsTypes... args) {
    MutatorType* obj = new MutatorType(GetRandomState(), args...);
    AddMutator(obj);
    return obj;
  }
};

}  // namespace afl
