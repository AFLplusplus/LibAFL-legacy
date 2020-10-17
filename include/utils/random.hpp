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

#ifndef LIBAFL_UTILS_RANDOM_H
#define LIBAFL_UTILS_RANDOM_H

#include "types.hpp"
#include "debug.hpp"
#include "utils/xxh3.h"
#include "utils/misc.hpp"

#define HASH_CONST 0xa5b35705

namespace afl {

class RandomState {

  u64  randSeed[4];
  u64  initSeed;

public:

  RandomState(u64 init_seed) : initSeed(init_seed) {
    SetSeed(init_seed);
  }
  RandomState() : RandomState(0) {}

  void SetSeed(u64 seed) {

    randSeed[0] = XXH64((u8 *)&seed, sizeof(seed), HASH_CONST);
    randSeed[1] = randSeed[0] ^ 0x1234567890abcdef;
    randSeed[2] = randSeed[0] & 0x0123456789abcdef;
    randSeed[3] = randSeed[0] | 0x01abcde43f567908;

  }
  
  inline u64 Next() {
  
    const u64 result = Rotl(randSeed[0] + randSeed[3], 23) + randSeed[0];
    const u64 t = randSeed[1] << 17;

    randSeed[2] ^= randSeed[0];
    randSeed[3] ^= randSeed[1];
    randSeed[1] ^= randSeed[2];
    randSeed[0] ^= randSeed[3];

    randSeed[2] ^= t;

    randSeed[3] = Rotl(randSeed[3], 45);

    return result;
  
  }
  
  inline u64 Below(u64 limit) {

    if (limit <= 1) return 0;

    /*
      Modulo is biased - we don't want our fuzzing to be biased so let's do it right.
      See https://stackoverflow.com/questions/10984974/why-do-people-say-there-is-modulo-bias-when-using-a-random-number-generator
    */
    u64 unbiased_rnd;
    do
      unbiased_rnd = Next();
    while (unlikely(unbiased_rnd >= (UINT64_MAX - (UINT64_MAX % limit))));

    return unbiased_rnd % limit;

  }
  
  inline u64 Between(u64 min, u64 max) {
    
    DCHECK(max > min);
    return min + Below(max - min + 1); 
    
  }
  
};

} // namespace afl

#endif                                                                                                /* AFL_RAND_H */

