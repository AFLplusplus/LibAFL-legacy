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

#ifndef LIBAFL_TYPES_H
#define LIBAFL_TYPES_H

#include <cstdint>
#include <cstddef>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#ifndef MIN

  #define MIN(a, b)           \
    ({                        \
                              \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a < _b ? _a : _b;      \
                              \
    })

  #define MAX(a, b)           \
    ({                        \
                              \
      __typeof__(a) _a = (a); \
      __typeof__(b) _b = (b); \
      _a > _b ? _a : _b;      \
                              \
    })

#endif                                                                                                      /* !MIN */

#define SWAP16(_x)                    \
  ({                                  \
                                      \
    u16 _ret = (_x);                  \
    (u16)((_ret << 8) | (_ret >> 8)); \
                                      \
  })

#define SWAP32(_x)                                                                                \
  ({                                                                                              \
                                                                                                  \
    u32 _ret = (_x);                                                                              \
    (u32)((_ret << 24) | (_ret >> 24) | ((_ret << 8) & 0x00FF0000) | ((_ret >> 8) & 0x0000FF00)); \
                                                                                                  \
  })

#define SWAP64(_x)                                                                \
  ({                                                                              \
                                                                                  \
    u64 _ret = (_x);                                                              \
    _ret = (_ret & 0x00000000FFFFFFFF) << 32 | (_ret & 0xFFFFFFFF00000000) >> 32; \
    _ret = (_ret & 0x0000FFFF0000FFFF) << 16 | (_ret & 0xFFFF0000FFFF0000) >> 16; \
    _ret = (_ret & 0x00FF00FF00FF00FF) << 8 | (_ret & 0xFF00FF00FF00FF00) >> 8;   \
    _ret;                                                                         \
                                                                                  \
  })
  
#define MEM_BARRIER() __asm__ volatile("" ::: "memory")

#if __GNUC__ < 6
  #ifndef likely
    #define likely(_x) (_x)
  #endif
  #ifndef unlikely
    #define unlikely(_x) (_x)
  #endif
#else
  #ifndef likely
    #define likely(_x) __builtin_expect(!!(_x), 1)
  #endif
  #ifndef unlikely
    #define unlikely(_x) __builtin_expect(!!(_x), 0)
  #endif
#endif

#endif
