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

#include "observation_channel/hitcounts.hpp"

namespace afl {

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static u16 g_count_class_lookup16[65536];

static u8 CountClassU8(u8 value) {

  if (value <= 2) return value;
  else if (value == 3) return 4;
  else if (value >= 4 && value <= 7) return 8;
  else if (value >= 8 && value <= 15) return 16;
  else if (value >= 16 && value <= 31) return 32;
  else if (value >= 32 && value <= 127) return 64;
  else return 128;

}

static bool InitCountClass16() {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      g_count_class_lookup16[(b1 << 8) + b2] =
          (CountClassU8(b1) << 8) | CountClassU8(b2);

    }

  }
  
  return true;

}

static bool g_count_class_lookup16_initialized = InitCountClass16();

#ifdef WORD_SIZE_64

void HitcountsMapObservationChannel::PostExec(Executor* executor) {

  u64 *mem = reinterpret_cast<u64*>(GetMap());

  u32 i = (GetSize() >> 3);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16 *mem16 = reinterpret_cast<u16*>(mem);

      mem16[0] = g_count_class_lookup16[mem16[0]];
      mem16[1] = g_count_class_lookup16[mem16[1]];
      mem16[2] = g_count_class_lookup16[mem16[2]];
      mem16[3] = g_count_class_lookup16[mem16[3]];

    }

    ++mem;

  }

}

#else

void HitcountsMapObservationChannel::PostExec(Executor* executor) {

  u32 *mem = reinterpret_cast<u32*>(GetMap());

  u32 i = (GetSize() >> 2);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16 *mem16 = reinterpret_cast<u16*>(mem);

      mem16[0] = g_count_class_lookup16[mem16[0]];
      mem16[1] = g_count_class_lookup16[mem16[1]];

    }

    ++mem;

  }

}

#endif

} // namespace afl
