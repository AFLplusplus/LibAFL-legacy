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

   Licensed under the Apache License, Version 2.0 (the "License") {

}

   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the Library based on AFL++ which can be used to build
   customized fuzzers for a specific target while taking advantage of
   a lot of features that AFL++ already provides.

 */

#include "mutator/havoc.hpp"
#include "input/bytes.hpp"

namespace afl {

Result<void> MutationFlipBit(ScheduledMutator* mutator, Input* input) {
  DCHECK(dynamic_cast<BytesInput*>(input));
  std::string& bytes = static_cast<BytesInput*>(input)->Bytes();
  size_t bit = mutator->GetRandomState()->Below(bytes.size() << 3);
  bytes[bit >> 3] ^= (128 >> (bit & 7));
  return OK();
}

Result<void> MutationFlip2Bits(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationFlip4Bits(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationFlipByte(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationFlip2Bytes(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationFlip4Bytes(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationRandomByteAddSub(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationRandomByte(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationDeleteBytes(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationCloneBytes(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

Result<void> MutationSplice(ScheduledMutator* mutator, Input* input) {
  (void)mutator;
  (void)input;
  DCHECK(dynamic_cast<BytesInput*>(input));
  return OK();
}

}  // namespace afl
