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


 */

#ifndef LIBMUTATOR_H
#define LIBMUTATOR_H

#include "input.h"
#include "queue.h"
#include "engine.h"

// Mutator struct will have many internal functions like mutate, trimming etc.
// This is based on both the FFF prototype and the custom mutators that we have
// in AFL++ without the AFL++ specific parts

struct afl_mutator_funcs {

  void (*init)(afl_mutator_t *);

  // The params here are in_buf and out_buf.
  size_t (*trim)(afl_mutator_t *, afl_input_t *);

  // Mutate function
  size_t (*mutate)(afl_mutator_t *, afl_input_t *);

  // Checks if the queue entry is to be fuzzed or not
  afl_ret_t (*custom_queue_get)(afl_mutator_t *, afl_input_t *);
  void (*custom_queue_new_entry)(afl_mutator_t *, afl_entry_t *);
  // Post process API AFL++
  void (*post_process)(afl_mutator_t *, afl_input_t *);

  afl_stage_t *(*get_stage)(afl_mutator_t *);

};

struct afl_mutator {

  afl_engine_t *engine;
  u8 *          mutate_buf;  // Extra buf for mutators to work with for afl_realloc

  struct afl_mutator_funcs funcs;

};

size_t       afl_mutator_trim(afl_mutator_t *, u8 *, u8 *);
afl_stage_t *afl_mutator_get_stage(afl_mutator_t *);

afl_ret_t afl_mutator_init(afl_mutator_t *, afl_engine_t *);
void      afl_mutator_deinit(afl_mutator_t *);

// A simple scheduled mutator based on the above mutator. Will act something
// similar to the havoc stage

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_mutator, AFL_DECL_PARAMS(afl_engine_t *engine), AFL_CALL_PARAMS(engine))

typedef struct afl_mutator_scheduled afl_mutator_scheduled_t;
typedef void (*afl_mutator_func)(afl_mutator_t *, afl_input_t *);

struct afl_mutator_scheduled_funcs {

  size_t (*schedule)(afl_mutator_scheduled_t *);
  afl_ret_t (*add_func)(afl_mutator_scheduled_t *, afl_mutator_func);
  afl_ret_t (*add_default_funcs)(afl_mutator_scheduled_t *);
  size_t (*get_iters)(afl_mutator_scheduled_t *);

};

struct afl_mutator_scheduled {

  afl_mutator_t     base;
  afl_mutator_func *mutations;  // A ptr to an array of mutation operator
                                // functions
  size_t                             mutators_count;
  struct afl_mutator_scheduled_funcs funcs;
  size_t                             max_iterations;

};

/* TODO add implementation for the _schedule_ and _iterations_ functions, need a
 * random list element pop type implementation for this */
size_t afl_iterations(afl_mutator_scheduled_t *);
/* Add a mutator func to this mutators */
afl_ret_t afl_mutator_add_func(afl_mutator_scheduled_t *, afl_mutator_func);
/* Add all default mutator funcs */
afl_ret_t afl_mutator_scheduled_add_havoc_funcs(afl_mutator_scheduled_t *mutator);
size_t    afl_schedule(afl_mutator_scheduled_t *);
size_t    afl_mutate_scheduled_mutator(afl_mutator_t *, afl_input_t *);

afl_ret_t afl_mutator_scheduled_init(afl_mutator_scheduled_t *sched_mut, afl_engine_t *engine, size_t max_iterations);
void      afl_mutator_scheduled_deinit(afl_mutator_scheduled_t *);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_mutator_scheduled, AFL_DECL_PARAMS(afl_engine_t *engine, size_t max_iterations),
                                   AFL_CALL_PARAMS(engine, max_iterations))

void afl_mutfunc_flip_bit(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_flip_2_bits(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_flip_4_bits(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_flip_byte(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_flip_2_bytes(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_flip_4_bytes(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_random_byte_add_sub(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_random_byte(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_delete_bytes(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_clone_bytes(afl_mutator_t *mutator, afl_input_t *input);
void afl_mutfunc_splice(afl_mutator_t *mutator, afl_input_t *input);

#endif

