#include <stdio.h>
#include <string.h>
#ifdef USEMMAP
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/mman.h>
  #include <sys/types.h>
#else
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif

#ifdef __ANDROID__
  #include "android-ashmem.h"
#endif

#include "types.h"
#include "shmem.h"

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

    close(shm->g_shm_fd);
    shm_unlink(shm->shm_str);
    shm->shm_str[0] = '\0';
    return NULL;

  }

  /* map the shared memory segment to the address space of the process */
  shm->map = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
  if (shm->map == MAP_FAILED || shm->map == ((void *)-1) || !shm->map) {

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
  shm_base = mmap(0, shm->map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm->g_shm_fd, 0);
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

/* Write sharedmap as env var and the size as name#_SIZE */
afl_ret_t afl_shmem_to_env_var(afl_shmem_t *shmem, char *env_name) {

  if (!env_name || !shmem || !env_name[0] || !shmem->shm_str[0] || strlen(env_name) > 200) { return AFL_RET_NULL_PTR; }

  char shm_str[256];
  snprintf(shm_str, sizeof(shm_str), "%d", shmem->shm_id);
  if (setenv(env_name, (char *)shm_str, 1) < 0) { return AFL_RET_ERRNO; }

  /* Write the size to env, too */
  char size_env_name[256];
  snprintf(size_env_name, sizeof(size_env_name), "%s_SIZE", env_name);
  snprintf(shm_str, sizeof(shm_str), "%d", shmem->shm_id);
  if (setenv(size_env_name, (char *)shm_str, 1) < 0) { return AFL_RET_ERRNO; }

  return AFL_RET_SUCCESS;

}

