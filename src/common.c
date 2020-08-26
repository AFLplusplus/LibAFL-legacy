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

#include <sys/ipc.h>
#include <sys/shm.h>
#include "common.h"
#include "afl-shmem.h"

void afl_shmem_deinit(afl_shmem_t *shm) {

  if (!shm || !shm->map) {

    // Not set or not initialized;
    return;

  }

  shm->shm_str[0] = '\0';

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

u8 *afl_shmem_init(afl_shmem_t *shm, size_t map_size) {

  shm->map_size = map_size;

  shm->map = NULL;

#ifdef USEMMAP

  shm->g_shm_fd = -1;

  /* ======
  generate random file name for multi instance

  thanks to f*cking glibc we can not use tmpnam securely, it generates a
  security warning that cannot be suppressed
  so we do this worse workaround */
  snprintf(shm->shm_str, 20, "/afl_%d_%ld", getpid(), random());

  /* create the shared memory segment as if it was a file */
  shm->g_shm_fd = shm_open(shm->shm_str, O_CREAT | O_RDWR | O_EXCL, 0600);
  if (shm->g_shm_fd == -1) {

    shm->shm_str[0] = '\0';
    return NULL;

  }

  /* configure the size of the shared memory segment */
  if (ftruncate(shm->g_shm_fd, map_size)) {

    clos(shm->g_shm_fd);
    shm_unlink(shm->shm_str);
    shm->shm_str[0] = '\0';
    return NULL;

  }

  /* map the shared memory segment to the address space of the process */
  shm->map =
      mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
  if (shm->map == MAP_FAILED || shm->map == -1 || !shm->map) {

    close(shm->g_shm_fd);
    shm_unlink(shm->shm_str);
    shm->g_shm_fd = -1;
    shm->shm_str[0] = '\0';
    return NULL;

  }

#else

  shm->shm_id = shmget(IPC_PRIVATE, map_size, IPC_CREAT | IPC_EXCL | 0600);

  if (shm->shm_id < 0) {

    shm->shm_str[0] = '\0';
    return NULL;

  }

  snprintf(shm->shm_str, sizeof(shm->shm_str), "%d", shm->shm_id);
  shm->shm_str[sizeof(shm->shm_str) - 1] = '\0';

  shm->map = shmat(shm->shm_id, NULL, 0);

  if (shm->map == (void *)-1 || !shm->map) {

    shmctl(shm->shm_id, IPC_RMID, NULL);
    shm->shm_id = -1;
    shm->shm_str[0] = '\0';
    return NULL;

  }

#endif

  return shm->map;

}

u8 *afl_shmem_by_str(afl_shmem_t *shm, char *shm_str, size_t map_size) {

  if (!shm || !shm_str || !shm_str[0] || !map_size) { return NULL; }
  shm->map = NULL;

  shm->map_size = map_size;
  strncpy(shm->shm_str, shm_str, sizeof(shm->shm_str) - 1);

#ifdef USEMMAP
  const char *   shm_file_path = shm_str;
  unsigned char *shm_base = NULL;

  /* create the shared memory segment as if it was a file */
  shm->g_shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
  if (shm->g_shm_fd == -1) {

    shm->shm_str[0] = '\0';
    return NULL;

  }

  /* map the shared memory segment to the address space of the process */
  shm_base =
      mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
  if (shm_base == MAP_FAILED) {

    close(shm->g_shm_fd);
    shm->g_shm_fd = -1;
    shm->map_size = 0;
    shm->shm_str[0] = '\0';

    return NULL;

  }

  shm->map = shm_base;
#else
  shm->shm_id = atoi(shm_str);

  shm->map = shmat(shm->shm_id, NULL, 0);

  if (shm->map == (void *)-1) {

    shm->map = NULL;
    shm->map_size = 0;
    shm->shm_str[0] = '\0';
    return NULL;

  }

#endif

  return shm->map;

}

/* Few helper functions */

void *afl_insert_substring(u8 *buf, size_t len, void *token, size_t token_len,
                           size_t offset) {

  void *new_buf = calloc(len + token_len + 1, 1);
  memmove(new_buf, buf, offset);

  memmove(new_buf + offset, token, token_len);

  memmove(new_buf + offset + token_len, buf + offset, len - offset);

  return new_buf;

}

/* This function inserts given number of bytes at a certain offset in a string
  and returns a ptr to the newly allocated memory. NOTE: You have to free the
  original memory(if malloced) yourself*/
u8 *afl_insert_bytes(u8 *buf, size_t len, u8 byte, size_t insert_len,
                     size_t offset) {

  u8 *new_buf = calloc(len + insert_len + 1, 1);

  memmove(new_buf, buf, offset);

  memset(new_buf + offset, byte, insert_len);

  memmove(new_buf + offset + insert_len, buf + offset, len - offset);

  return new_buf;

}

size_t afl_erase_bytes(u8 *buf, size_t len, size_t offset, size_t remove_len) {

  memmove(buf + offset, buf + offset + remove_len, len - offset - remove_len);
  memset(buf + len - remove_len, 0x0, remove_len);

  size_t new_size = len - remove_len;

  return new_size;

}

