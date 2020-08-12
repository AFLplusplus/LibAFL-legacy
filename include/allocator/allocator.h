#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdio.h>

#include "types.h"
#include "debug.h"

typedef struct allocator {

  void* (*alloc)(struct allocator*, size_t);
  void* (*alloc_nozero)(struct allocator*, size_t);
  void (*dealloc)(struct allocator*, void*);

} allocator_t;

extern allocator_t* afl_allocator_instance;

static inline void afl_register_allocator(allocator_t* instance) {

  afl_allocator_instance = instance;

}

static inline void* afl_alloc(size_t size) {

  if (!afl_allocator_instance) FATAL("allocator not initialized");
  
  return afl_allocator_instance->alloc(afl_allocator_instance, size);

}

static inline void* afl_alloc_nozero(size_t size) {

  if (!afl_allocator_instance) FATAL("allocator not initialized");
  
  return afl_allocator_instance->alloc_nozero(afl_allocator_instance, size);

}

static inline void afl_dealloc(void* ptr) {

  if (!afl_allocator_instance) FATAL("allocator not initialized");
  
  afl_allocator_instance->dealloc(afl_allocator_instance, ptr);

}

#endif
