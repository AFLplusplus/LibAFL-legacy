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

#ifndef LIBAFL_MUTATOR_HAVOC_H
#define LIBAFL_MUTATOR_HAVOC_H

#include "corpus/corpus.hpp"
#include "mutator/scheduled.hpp"

namespace afl {

void MutationFlipBit(ScheduledMutator* mutator, Input* input);
void MutationFlip2Bits(ScheduledMutator* mutator, Input* input);
void MutationFlip4Bits(ScheduledMutator* mutator, Input* input);
void MutationFlipByte(ScheduledMutator* mutator, Input* input);
void MutationFlip2Bytes(ScheduledMutator* mutator, Input* input);
void MutationFlip4Bytes(ScheduledMutator* mutator, Input* input);
void MutationRandomByteAddSub(ScheduledMutator* mutator, Input* input);
void MutationRandomByte(ScheduledMutator* mutator, Input* input);
void MutationDeleteBytes(ScheduledMutator* mutator, Input* input);
void MutationCloneBytes(ScheduledMutator* mutator, Input* input);
void MutationSplice(ScheduledMutator* mutator, Input* input);

class HavocMutator : public ScheduledMutator {
  Corpus* corpus;

 public:
  HavocMutator(RandomState* random_state, Corpus* corpus_)
      : ScheduledMutator(random_state), corpus(corpus_) {
    AddMutation(MutationFlipBit);
    AddMutation(MutationFlip2Bits);
    AddMutation(MutationFlip4Bits);
    AddMutation(MutationFlipByte);
    AddMutation(MutationFlip2Bytes);
    AddMutation(MutationFlip4Bytes);
    AddMutation(MutationRandomByteAddSub);
    AddMutation(MutationRandomByte);
    AddMutation(MutationDeleteBytes);
    AddMutation(MutationCloneBytes);
    if (corpus)
      AddMutation(MutationSplice);
  }
  HavocMutator(RandomState* random_state)
      : HavocMutator(random_state, nullptr) {}
};

}  // namespace afl

#endif
