#ifndef SHMEM_ALLOCATOR_H
#define SHMEM_ALLOCATOR_H

#include "os/ipc.h"

typedef struct shmem_allocator {

  allocator_t base;
  
  void* mmapped;
  size_t size;

} shmem_allocator_t;

void* afl_shmem_allocator_alloc(struct allocator*, size_t) {

   

}

#endif
