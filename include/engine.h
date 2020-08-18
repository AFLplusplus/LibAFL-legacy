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

   The Engine is the main and central part of the fuzzer. It contains the
   queues, feedbacks, executor and the fuzz_one (which in turn has stages)

 */

#ifndef LIBENGINE_H
#define LIBENGINE_H

#include <unistd.h>

#include "common.h"
#include "queue.h"
#include "aflpp.h"
#include "feedback.h"
#include "afl-returns.h"

#define MAX_FEEDBACKS 10

struct engine_functions {

  global_queue_t *(*get_queue)(engine_t *);
  fuzz_one_t *(*get_fuzz_one)(engine_t *);
  u64 (*get_execs)(engine_t *);
  u64 (*get_start_time)(engine_t *);

  void (*set_fuzz_one)(engine_t *, fuzz_one_t *);
  int (*add_feedback)(engine_t *, feedback_t *);
  void (*set_global_queue)(engine_t *, global_queue_t *);

  u8 (*execute)(engine_t *, raw_input_t *);
  afl_ret_t (*load_testcases_from_dir)(
      engine_t *, char *, raw_input_t *(*custom_input_init)(u8 *buf));
  void (*load_zero_testcase)(size_t);

  afl_ret_t (*loop)(engine_t *);

};

struct engine {

  fuzz_one_t *      fuzz_one;
  global_queue_t *  global_queue;
  executor_t *      executor;
  feedback_queue_t *current_feedback_queue;
  feedback_t
      *feedbacks[MAX_FEEDBACKS];  // We're keeping a pointer of feedbacks here
                                  // to save memory, consideting the original
                                  // feedback would already be allocated
  u64 executions, start_time, crashes, feedbacks_num;
  int id;
  u32 rand_cnt;                         /* Random number counter*/
  u64 rand_seed[4];
  s32 dev_urandom_fd;

  struct engine_functions funcs;

};

/* TODO: Add default implementations for load_testcases and execute */
global_queue_t *afl_get_queue_default(engine_t *);
fuzz_one_t *    afl_get_fuzz_one_default(engine_t *);
u64             afl_get_execs_defualt(engine_t *);
u64             afl_get_start_time_default(engine_t *);

void afl_set_fuzz_one_default(engine_t *, fuzz_one_t *);
int  afl_add_feedback_default(engine_t *, feedback_t *);
void afl_set_global_queue_default(engine_t *engine, global_queue_t *global_queue);

u8        afl_execute_default(engine_t *, raw_input_t *);
afl_ret_t afl_load_testcases_from_dir_default(engine_t *, char *,
                                          raw_input_t *(*custom_input_init)());
void      afl_load_zero_testcase_default(size_t);

afl_ret_t afl_loop_default(engine_t *);  // Not sure about this functions use-case.
                                     // Was in FFF though.

afl_ret_t afl_engine_init(engine_t *, executor_t *, fuzz_one_t *,
                          global_queue_t *);
void      afl_engine_deinit(engine_t *);

static inline engine_t *afl_engine_create(executor_t *    executor,
                                          fuzz_one_t *    fuzz_one,
                                          global_queue_t *global_queue) {

  engine_t *engine = calloc(1, sizeof(engine_t));
  if (!engine) return NULL;
  if (afl_engine_init(engine, executor, fuzz_one, global_queue) !=
      AFL_RET_SUCCESS) {

    free(engine);
    return NULL;

  }

  return engine;

}

static inline void afl_engine_delete(engine_t *engine) {

  afl_engine_deinit(engine);
  free(engine);

}

static inline u64 rotl(const u64 x, int k) {

  return (x << k) | (x >> (64 - k));

}

static u64 afl_rand_next_engine(engine_t *engine) {

  const uint64_t result =
      rotl(engine->rand_seed[0] + engine->rand_seed[3], 23) + engine->rand_seed[0];

  const uint64_t t = engine->rand_seed[1] << 17;

  engine->rand_seed[2] ^= engine->rand_seed[0];
  engine->rand_seed[3] ^= engine->rand_seed[1];
  engine->rand_seed[1] ^= engine->rand_seed[2];
  engine->rand_seed[0] ^= engine->rand_seed[3];

  engine->rand_seed[2] ^= t;

  engine->rand_seed[3] = rotl(engine->rand_seed[3], 45);

  return result;

}

static inline u64 afl_rand_below_engine(engine_t *engine, u64 limit) {

  if (limit <= 1) return 0;

  /* The boundary not being necessarily a power of 2,
     we need to ensure the result uniformity. */
  if (unlikely(!engine->rand_cnt--)) {

    int read_len = read(engine->dev_urandom_fd, &engine->rand_seed, sizeof(engine->rand_seed));
    (void)  read_len;
    engine->rand_cnt = (RESEED_RNG / 2) + (engine->rand_seed[1] % RESEED_RNG);

  }

  return afl_rand_next_engine(engine) % limit;

}

#endif

