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

#ifndef LIBAFL_OBJECT_H
#define LIBAFL_OBJECT_H

#include "types.h"

#define INHERITS(name) struct name base;
#define BASE_CAST(obj) ((obj)->base)

#define AFL_DECL_PARAMS(...) __VA_ARGS__
#define AFL_CALL_PARAMS(...) ret, __VA_ARGS__

#define AFL_NEW_FOR(init_type) AFL_NEW_FOR_WITH_PARAMS(init_type, AFL_DECL_PARAMS(void), ret)

/*
This makro wraps all our afl_ ... _init and _deinit calls with _new and _delete wrappers.
The _new wrapper allocates memory, and return NULL or the pointer, depending on result.
The _delete wrapper calls _denit and deallocates the pointer, as created by _new.
For decl and call, use AFL_DECL/CALL_PARAMS
*/
#define AFL_NEW_FOR_WITH_PARAMS(init_type, decl_params, call_params)      \
  static inline init_type##_t *init_type##_new(decl_params) {                        \
                                                                                     \
    /*printf("Allocating " #init_type " with decl_params " #decl_params */           \
    /*" and call params " #call_params " and size %ld\n", sizeof(init_type##_t) );*/ \
    init_type##_t *ret = calloc(1, sizeof(init_type##_t));                           \
    if (!ret) { return NULL; }                                                       \
    if (init_type##_init(call_params) != AFL_RET_SUCCESS) {                          \
                                                                                     \
      free(ret);                                                                     \
      return NULL;                                                                   \
                                                                                     \
    }                                                                                \
    return ret;                                                                      \
                                                                                     \
  }                                                                                  \


#define AFL_DELETE_FOR(init_type)  \
  static inline void init_type##_delete(init_type##_t *init_type) {                  \
                                                                                     \
    init_type##_destroy(init_type);                                                   \
    free(init_type);                                                                 \
                                                                                     \
  }

struct afl_object {

  void* wrapper;

};

#endif
