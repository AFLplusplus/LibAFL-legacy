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

#ifndef LIBAFL_CORPUS_CORPUS_H
#define LIBAFL_CORPUS_CORPUS_H

#include "errors.hpp"
#include "result.hpp"

#include "corpus/entry.hpp"
#include "utils/random.hpp"

#include <algorithm>
#include <vector>

namespace afl {

class Corpus {
 protected:
  std::vector<Entry*> entries;

  char dirPath[PATH_MAX];
  u8 isOnDisk;

  RandomState* randomState;

 public:
  Corpus(RandomState* random_state) : randomState(random_state) {}

  RandomState* GetRandomState() { return randomState; }

  void SetRandomState(RandomState* random_state) { randomState = random_state; }

  size_t GetEntriesCount() { return entries.size(); }

  virtual void Insert(Entry* entry) {
    entries.push_back(entry);
  }

  virtual bool Remove(Entry* entry) {
    auto it = std::find(entries.begin(), entries.end(), entry);
    if (it != entries.end()) {
      entries.erase(it);
      return true;
    }
    return false;
  }

  Result<Entry*> GetByIndex(size_t index) {
    if (index >= GetEntriesCount())
      return ERR(OutOfBoundsError);
    return entries[index];
  }

  Result<Entry*> GetRandom() {
    if (GetEntriesCount() == 0)
      return ERR(EmptyContainerError);
    return GetByIndex(randomState->Below(GetEntriesCount()));
  }

  virtual Result<Entry*> Get() { return GetRandom(); }
};

}  // namespace afl

#endif
