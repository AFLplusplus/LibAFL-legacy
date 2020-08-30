/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#ifndef __AFL_QEMU_COMMON
#define __AFL_QEMU_COMMON

#include "../../config.h"
#include "../../include/cmplog.h"

#define PERSISTENT_DEFAULT_MAX_CNT 1000

#ifdef CPU_NB_REGS
  #define AFL_REGS_NUM CPU_NB_REGS
#elif TARGET_ARM
  #define AFL_REGS_NUM 16
#elif TARGET_AARCH64
  #define AFL_REGS_NUM 32
#else
  #define AFL_REGS_NUM 100
#endif

/* NeverZero */

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
  #define INC_AFL_AREA(loc)           \
    asm volatile(                     \
        "addb $1, (%0, %1, 1)\n"      \
        "adcb $0, (%0, %1, 1)\n"      \
        : /* no out */                \
        : "r"(afl_area_ptr), "r"(loc) \
        : "memory", "eax")
#else
  #define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif

typedef void (*afl_persistent_hook_fn)(uint64_t *regs, uint64_t guest_base,
                                       uint8_t *input_buf,
                                       uint32_t input_buf_len);

/* Declared in afl-qemu-cpu-inl.h */

extern unsigned char *afl_area_ptr;
extern unsigned int   afl_inst_rms;
extern abi_ulong      afl_entry_point, afl_start_code, afl_end_code;
extern abi_ulong      afl_persistent_addr;
extern abi_ulong      afl_persistent_ret_addr;
extern u8             afl_compcov_level;
extern unsigned char  afl_fork_child;
extern unsigned char  is_persistent;
extern target_long    persistent_stack_offset;
extern unsigned char  persistent_first_pass;
extern unsigned char  persistent_save_gpr;
extern uint64_t       persistent_saved_gpr[AFL_REGS_NUM];
extern int            persisent_retaddr_offset;

extern u8 * shared_buf;
extern u32 *shared_buf_len;
extern u8   sharedmem_fuzzing;

extern afl_persistent_hook_fn afl_persistent_hook_ptr;

extern __thread abi_ulong afl_prev_loc;

extern struct cmp_map *__afl_cmp_map;
extern __thread u32    __afl_cmp_counter;

void afl_setup(void);
void afl_forkserver(CPUState *cpu);

// void afl_debug_dump_saved_regs(void);

void afl_persistent_loop(void);

void afl_gen_tcg_plain_call(void *func);

void afl_float_compcov_log_32(target_ulong cur_loc, float32 arg1, float32 arg2,
                              void *status);
void afl_float_compcov_log_64(target_ulong cur_loc, float64 arg1, float64 arg2,
                              void *status);
void afl_float_compcov_log_80(target_ulong cur_loc, floatx80 arg1,
                              floatx80 arg2);

/* Check if an address is valid in the current mapping */

static inline int is_valid_addr(target_ulong addr) {

  int          flags;
  target_ulong page;

  page = addr & TARGET_PAGE_MASK;

  flags = page_get_flags(page);
  if (!(flags & PAGE_VALID) || !(flags & PAGE_READ)) return 0;

  return 1;

}

#endif

