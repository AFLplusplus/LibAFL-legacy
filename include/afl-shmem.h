#ifndef AFL_SHMEM_H
#define AFL_SHMEM_H

#include "types.h"

#define AFL_SHMEM_STRLEN_MAX (20)

// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)

typedef struct afl_shmem {

  /* Serialized map id */
  char shm_str[AFL_SHMEM_STRLEN_MAX];
#ifdef USEMMAP
  int g_shm_fd;
#else
  int shm_id;
#endif

  u8 *   map;
  size_t map_size;

} afl_shmem_t;

// Functions to create Shared memory region, for observation channels and
// opening inputs and stuff.
u8 * afl_shmem_init(afl_shmem_t *sharedmem, size_t map_size);
u8 * afl_shmem_by_str(afl_shmem_t *shm, char *shm_str, size_t map_size);
void afl_shmem_deinit(afl_shmem_t *sharedmem);

#endif                                                                                               /* AFL_SHMEM_H */

