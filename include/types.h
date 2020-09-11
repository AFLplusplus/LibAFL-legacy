/*
   american fuzzy lop++ - type definitions and minor macros
   --------------------------------------------------------

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

 */

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <stdlib.h>

#include "afl-returns.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

/* Extended forkserver option values */

/* Reporting errors */
#define FS_OPT_ERROR 0xf800008f
#define FS_OPT_GET_ERROR(x) ((x & 0x00ffff00) >> 8)
#define FS_OPT_SET_ERROR(x) ((x & 0x0000ffff) << 8)
#define FS_ERROR_MAP_SIZE 1
#define FS_ERROR_MAP_ADDR 2
#define FS_ERROR_SHM_OPEN 4
#define FS_ERROR_SHMAT 8
#define FS_ERROR_MMAP 16

/* Reporting options */
#define FS_OPT_ENABLED 0x80000001
#define FS_OPT_MAPSIZE 0x40000000
#define FS_OPT_SNAPSHOT 0x20000000
#define FS_OPT_AUTODICT 0x10000000
#define FS_OPT_SHDMEM_FUZZ 0x01000000
#define FS_OPT_OLD_AFLPP_WORKAROUND 0x0f000000
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
#define FS_OPT_MAX_MAPSIZE ((0x00fffffe >> 1) + 1)
#define FS_OPT_GET_MAPSIZE(x) (((x & 0x00fffffe) >> 1) + 1)
#define FS_OPT_SET_MAPSIZE(x) (x <= 1 || x > FS_OPT_MAX_MAPSIZE ? 0 : ((x - 1) << 1))

typedef unsigned long long u64;

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

#ifdef AFL_LLVM_PASS
  #if defined(__linux__) || !defined(__ANDROID__)
    #define AFL_SR(s) (srandom(s))
    #define AFL_R(x) (random() % (x))
  #else
    #define AFL_SR(s) ((void)s)
    #define AFL_R(x) (arc4random_uniform(x))
  #endif
#else
  #if defined(__linux__) || !defined(__ANDROID__)
    #define SR(s) (srandom(s))
    #define R(x) (random() % (x))
  #else
    #define SR(s) ((void)s)
    #define R(x) (arc4random_uniform(x))
  #endif
#endif                                                                                            /* ^AFL_LLVM_PASS */

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)

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

#define AFL_NEW_AND_DELETE_FOR(init_type) AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(init_type, AFL_DECL_PARAMS(void), ret)

/*
This makro wraps all our afl_ ... _init and _deinit calls with _new and _delete wrappers.
The _new wrapper allocates memory, and return NULL or the pointer, depending on result.
The _delete wrapper calls _denit and deallocates the pointer, as created by _new.
For decl and call, use AFL_DECL/CALL_PARAMS
*/
#define AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(init_type, decl_params, call_params) \
  static inline init_type##_t *init_type##_new(decl_params) {                   \
                                                                                \
    /*printf("Allocating " #init_type " with decl_params " #decl_params */ \
    /*" and call params " #call_params " and size %ld\n", sizeof(init_type##_t) );*/\
    init_type##_t *ret = calloc(1, sizeof(init_type##_t));                      \
    if (!ret) { return NULL; }                                                   \
    if (init_type##_init(call_params) != AFL_RET_SUCCESS) {                     \
                                                                                \
      free(ret);                                                                \
      return NULL;                                                              \
                                                                                \
    }                                                                           \
    return ret;                                                                 \
                                                                                \
  }                                                                             \
                                                                                \
  static inline void init_type##_delete(init_type##_t *init_type) {             \
                                                                                \
    init_type##_deinit(init_type);                                              \
    free(init_type);                                                            \
                                                                                \
  }

#define AFL_DECL_PARAMS(...) __VA_ARGS__
#define AFL_CALL_PARAMS(...) ret, __VA_ARGS__



#endif                                                                                           /* ! _HAVE_TYPES_H */

