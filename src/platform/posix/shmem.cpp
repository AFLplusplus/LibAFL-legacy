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

#include "platform/shmem.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>

#ifdef __ANDROID__
#include "android-ashmem.h"
#endif

using namespace afl;

Result<void> SharedMemory::Create(size_t size) {
  DCHECK(size);

  this->size = size;

  /*
    Generate random file name for multi instance.

    Thanks to f*cking glibc we can not use tmpnam securely, it generates a
    security warning that cannot be suppressed so we do this worse workaround.
  */
  snprintf(name, sizeof(name), "/afl_%d_%ld", getpid(), random());

  /* Create the shared memory segment as if it was a file */
  fd = shm_open(name, O_CREAT | O_RDWR | O_EXCL, 0600);
  if (fd < 0)
    return ERR(OSError, errno);

  /* Configure the size of the shared memory segment */
  if (ftruncate(fd, size)) {
    int saved_errno = errno;
    close(fd);
    shm_unlink(name);
    return ERR(OSError, saved_errno);
  }

  /* Map the shared memory segment to the address space of the process */
  mem = static_cast<u8*>(
      mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  if (mem == MAP_FAILED || mem == reinterpret_cast<u8*>(-1) || !mem) {
    int saved_errno = errno;
    mem = nullptr;
    close(fd);
    shm_unlink(name);
    return ERR(OSError, saved_errno);
  }

  return OK();
}

Result<void> SharedMemory::ByName(const char* name, size_t size) {
  DCHECK(name);
  DCHECK(name[0] != '\0');
  DCHECK(size);

  this->size = size;

  strncpy(this->name, name, sizeof(this->name) - 1);

  /* Create the shared memory segment as if it was a file */
  fd = shm_open(name, O_RDWR, 0600);
  if (fd < 0)
    return ERR(OSError, errno);

  /* map the shared memory segment to the address space of the process */
  mem = static_cast<u8*>(
      mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  if (mem == MAP_FAILED || mem == reinterpret_cast<u8*>(-1) || !mem) {
    int saved_errno = errno;
    mem = nullptr;
    close(fd);
    return ERR(OSError, saved_errno);
  }

  return OK();
}

Result<bool> SharedMemory::SetEnv(const char* env_name) {
  DCHECK(env_name);
  DCHECK(env_name[0] != '\0');
  DCHECK(size);

  if (!IsInited())
    return false;

  std::string tmp_str = std::to_string(fd);

  if (setenv(env_name, tmp_str.c_str(), 1) < 0)
    return ERR(OSError, errno);

  /* Write the size to env, too */
  std::string size_env_name = std::string(env_name) + "_SIZE";
  tmp_str = std::to_string(size);
  if (setenv(size_env_name.c_str(), tmp_str.c_str(), 1) < 0)
    return ERR(OSError, errno);

  return true;
}
