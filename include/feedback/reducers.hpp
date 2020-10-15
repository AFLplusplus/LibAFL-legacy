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

#ifndef LIBAFL_FEEDBACK_REDUCERS_H
#define LIBAFL_FEEDBACK_REDUCERS_H

#include <algorithm>

namespace afl {

template<typename T>
static inline T ReducerMax(T first, T second) {
  return first > second ? first : second;
}

template<typename T>
static inline T ReducerMin(T first, T second) {
  return first < second ? first : second;
}

// TODO use compilers builting like GCC's __builtin_clz
template<typename T>
static inline T ReducerLogBucket(T first, T second) {
  T hibit = 0;
  while (second > 1) {
    second >>= 1;
    hibit++;
  }
  return first | hibit;
}

template<typename T>
static inline T ReducerBitUnion(T first, T second) {
  return first | second;
}

template<typename T>
static inline T ReducerBitIntersection(T first, T second) {
  return first & second;
}

} // namespace afl

#endif
