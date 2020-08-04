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

#ifndef COMMON_FILE_INCLUDED
#define COMMON_FILE_INCLUDED

#include "types.h"
#include "alloc-inl.h"
// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

typedef struct afl_sharedmem {

#ifdef USEMMAP
  int  g_shm_id;
  char g_shm_file_path[20];
#else
  int shm_id;
#endif

  u8 *   map;
  size_t map_size;

} afl_sharedmem_t;

// Functions to create Shared memory region, for feedback and opening inputs and
// stuff.
u8 * afl_sharedmem_init(afl_sharedmem_t *, size_t);
void afl_sharedmem_deinit(afl_sharedmem_t *);

// We're declaring a few structs here which have an interdependency between them

typedef struct fuzz_one fuzz_one_t;

typedef struct engine engine_t;

typedef struct stage stage_t;

typedef struct executor executor_t;

// enum to mark common-error (and status) types across the library
enum common_status_flags { ALL_OK = 0, FILE_OPEN_ERROR = 1 };

#define IS_SAME_TYPE(x, type) _Generic(x, (type *) : true, default : false)

#define IS_DERIVED_TYPE(x, type) \
  _Generic(x->base, (type *) : true, default : false)

// Calling the functions in a "vtable" for a struct like this.  We pss a pointer
// to the "object here"
/* What can we do in case of an incompatible type here? since, this is a macro,
 * not sure about this.  */
#define GENERIC_VTABLE_CALL(struct_instance, struct_type, function_name, ...) \
  do {                                                                        \
                                                                              \
    if (IS_SAME_TYPE(x, struct_type *)) {                                     \
                                                                              \
      struct_instance->functions->function_name(struct_instance,              \
                                                ##__VA_ARGS__);               \
      return 0;                                                               \
                                                                              \
    } else if (IS_DERIVED_TYPE(struct_instance, struct_type)) {               \
                                                                              \
      (struct_type *)parent_class = &(struct_instance->base);                 \
      parent_class->functions->function_name(parent_class, ##__VA_ARGS__);    \
                                                                              \
    } else {                                                                  \
                                                                              \
    }                                                                         \
                                                                              \
  } while (0)

void * insert_substring(void *buf, size_t len, void *token, size_t token_len,
                        size_t offset);
int    rand_below(size_t limit);
size_t erase_bytes(void *buf, size_t len, size_t offset, size_t remove_len);
void * insert_bytes(void *buf, size_t len, u8 byte, size_t insert_len,
                    size_t offset);

#endif

