/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This the actual code for the library framework.

 */

#include "libaflpp.h"

afl_queue_t * afl_queue_init() {
    afl_queue_t * queue = ck_alloc(sizeof(afl_queue_t));

    queue->queue_current = NULL;
    queue->queue_top = NULL;

    queue->executor = NULL;
    queue->destroy_queue_entry = NULL;
    queue->init_queue_entry = NULL;
}

void afl_queue_deinit(afl_queue_t * queue) {

    struct afl_queue_entry * current;

    current = queue->queue_top;
    if (!current) FATAL("The queue is empty, cannot deinit");

    // Free each entry present in the queue.
    while (current) {
        struct afl_queue_entry * temp = current->next_queue_entry;

        ck_free(current);
        current = temp;
    }

    ck_free(queue); // Free the queue itself now.

    SAYF("queue has been deinited");

}

void afl_sharedmem_deinit(afl_sharedmem_t *shm) {

#ifdef USEMMAP
  if (shm->map != NULL) {

    munmap(shm->map, shm->map_size);
    shm->map = NULL;

  }

  if (shm->g_shm_fd != -1) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;

  }

#else
  shmctl(shm->shm_id, IPC_RMID, NULL);
#endif

  shm->map = NULL;

}

u8 * afl_sharedmem_init(afl_sharedmem_t *shm, size_t map_size) {

  shm->map_size = map_size;

  shm->map = NULL;

#ifdef USEMMAP

  shm->g_shm_fd = -1;

  /* ======
  generate random file name for multi instance

  thanks to f*cking glibc we can not use tmpnam securely, it generates a
  security warning that cannot be suppressed
  so we do this worse workaround */
  snprintf(shm->g_shm_file_path, L_tmpnam, "/afl_%d_%ld", getpid(), random());

  /* create the shared memory segment as if it was a file */
  shm->g_shm_fd =
      shm_open(shm->g_shm_file_path, O_CREAT | O_RDWR | O_EXCL, 0600);
  if (shm->g_shm_fd == -1) { PFATAL("shm_open() failed"); }

  /* configure the size of the shared memory segment */
  if (ftruncate(shm->g_shm_fd, map_size)) {

    PFATAL("setup_shm(): ftruncate() failed");

  }

  /* map the shared memory segment to the address space of the process */
  shm->map =
      mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
  if (shm->map == MAP_FAILED) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;
    PFATAL("mmap() failed");

  }

  if (shm->map == -1 || !shm->map) PFATAL("mmap() failed");

#else
  u8 *shm_str;

  shm->shm_id = shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | 0600);

  if (shm->shm_id < 0) { PFATAL("shmget() failed"); }

  shm_str = alloc_printf("%d", shm->shm_id);

  ck_free(shm_str);

  shm->map = shmat(shm->shm_id, NULL, 0);

  if (shm->map == (void *)-1 || !shm->map) { PFATAL("shmat() failed"); }

#endif

  return shm->map;

}


afl_executor_t * afl_executor_init() {
    
  afl_executor_t * executor = ck_alloc(sizeof(afl_executor_t));

  executor->current_input = NULL;

  // These function pointers can be given a default forkserver pointer here when it is ported, thoughts?
  struct afl_executor_operation * executor_ops = ck_alloc(sizeof(struct afl_executor_operation));
  executor->executor_ops = executor_ops;
  executor->executor_ops->destroy_cb = (void *)0x0;
  executor->executor_ops->init_cb = (void *)0x0;
  executor->executor_ops->place_input_cb = (void *)0x0;
  executor->executor_ops->run_target_cb = (void *)0x0;

  return executor;

}

void afl_executor_deinit(afl_executor_t * executor) {

  if (!executor) FATAL("Cannot free a NULL pointer");

  ck_free(executor);

}

/* This is the primary function for the entire library, for each executor, we would pass it to this function which
start fuzzing it, something similar to what afl_fuzz's main function does.
This will be the entrypoint of a new thread when it is created (for each executor instance).*/
void fuzz_start(afl_executor_t * executor) {

  while(1) {
    // Pre input writing stuff, probably mutations, feedback stuff etc.

    // Still need a bit of work before we can pass the extra arguments to the virtual functions
    if (executor->executor_ops->place_input_cb) executor->executor_ops->place_input_cb(executor, NULL, 0);

    executor->executor_ops->run_target_cb(executor, 0, NULL);

    // Post run functions, writing results to the "feedback", or whatever afl does right now.

  }

}

