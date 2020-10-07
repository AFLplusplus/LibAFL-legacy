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

#include "alloc.h"
#include "error.h"

#define AFL_INHERITS(type) struct type _base;
#define AFL_BASEOF(ptr) (&(ptr)->_base)

#define AFL_VTABLE_INHERITS(type) struct type##_vtable _base;
#define AFL_VTABLE_INIT_BASE_VPTR(type) ._base_vptr = (struct afl_object_vtable *)&type##_vtable_instance

#define AFL_VTABLEOF(type, ptr) ((struct type##_vtable *)(((struct afl_object *)(ptr))->vptr))

#define AFL_VTABLE_SET(ptr, vtable) ((struct afl_object *)(ptr))->vptr = (struct afl_object_vtable *)&vtable

// #define INSTANCE_OF(type, ptr) ((ptr)->v == &type##_vtable_instance)

#define AFL_INSTANCEOF(type, ptr)                                                       \
  ({                                                                                    \
                                                                                        \
    struct afl_object_vtable *_v = (struct afl_object_vtable *)&type##_vtable_instance; \
    while (_v) {                                                                        \
                                                                                        \
      if (_v == ((struct afl_object *)(ptr))->vptr) break;                              \
      _v = _v->_base_vptr;                                                              \
                                                                                        \
    }                                                                                   \
    !!_v;                                                                               \
                                                                                        \
  })

#define AFL_DYN_CAST(type, ptr) (INSTANCE_OF(type, ptr) ? (struct type *)(ptr) : NULL)

#define AFL_DECL_PARAMS(...) __VA_ARGS__
#define AFL_CALL_PARAMS(...) ret, __VA_ARGS__

#define AFL_NEW_FOR_WITH_PARAMS(type, decl_params, call_params) \
  static inline struct type *type##_new(decl_params) {          \
                                                                \
    struct type *ret = afl_alloc(sizeof(struct type));          \
    if (!ret) { return NULL; }                                  \
    if (type##_init(call_params) != AFL_RET_SUCCESS) {          \
                                                                \
      afl_free(ret);                                            \
      return NULL;                                              \
                                                                \
    }                                                           \
    return ret;                                                 \
                                                                \
  }

#define AFL_NEW_FOR(type) AFL_NEW_FOR_WITH_PARAMS(type, AFL_DECL_PARAMS(void), ret)

#define AFL_DELETE_FOR(type)                           \
  static inline void type##_delete(struct type *obj) { \
                                                       \
    type##_deinit(obj);                                \
    afl_free(obj);                                     \
                                                       \
  }

typedef struct afl_object afl_object_t;

struct afl_object_vtable {

  struct afl_object_vtable *_base_vptr;

  void *(*_create_wrapper)(void *);  // for bindings

  /*
    The deinit() method is optional.
    It is invoked just before the destroy of the object.
  */
  void (*deinit)(afl_object_t *);

};

struct afl_object_vtable afl_object_vtable_instance = {

    ._base_vptr = NULL,

    .deinit = NULL

};

struct afl_object {

  void *wrapper;  // for bindings

  struct afl_object_vtable *vptr;

};

static inline void afl_object_deinit(afl_object_t *self) {

  DCHECK(self);
  DCHECK(VTABLE_OF(afl_object, self));

  if (VTABLE_OF(afl_object, self)->deinit) VTABLE_OF(afl_object, self)->deinit(self);

}

AFL_DELETE_FOR(afl_object)

#endif
