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

// Mutator struct will have many internal functions like mutate, trimming etc.
// This is based on both the FFF prototype and the custom mutators that we have
// in AFL++ without the AFL++ specific parts

struct mutator_functions {

  void (*init)(afl_mutator_t *);  // Sort of like the afl_custom_init we have for
                                  // custom mutators?

  size_t (*trim)(afl_mutator_t *,
                 afl_raw_input_t *);  // The params here are in_buf and out_buf.

  size_t (*mutate)(afl_mutator_t *, afl_raw_input_t *);  // Mutate function
  afl_ret_t (*custom_queue_get)(afl_mutator_t *,
                                afl_raw_input_t *);  // Checks if the queue entry is to be fuzzed or not
  void (*custom_queue_new_entry)(afl_mutator_t *, afl_queue_entry_t *);
  void (*post_process)(afl_mutator_t *, afl_raw_input_t *);  // Post process API AFL++

  afl_stage_t *(*get_stage)(afl_mutator_t *);

};

struct afl_mutator {

  afl_stage_t *stage;

  struct mutator_functions funcs;

};

void         afl_mutator_init_default(afl_mutator_t *);
size_t       afl_trim_default(afl_mutator_t *, u8 *, u8 *);
afl_stage_t *afl_get_mutator_stage_default(afl_mutator_t *);

afl_ret_t afl_mutator_init(afl_mutator_t *, afl_stage_t *);
void      afl_mutator_deinit(afl_mutator_t *);

// A simple scheduled mutator based on the above mutator. Will act something
// similar to the havoc stage

static inline afl_mutator_t *afl_mutator_new(afl_stage_t *stage) {

  afl_mutator_t *mutator = calloc(1, sizeof(afl_mutator_t));
  if (!mutator) return NULL;
  if (afl_mutator_init(mutator, stage) == AFL_RET_SUCCESS) {

    free(mutator);
    return NULL;

  }

  return mutator;

}

static inline void afl_mutator_delete(afl_mutator_t *mutator) {

  afl_mutator_deinit(mutator);
  free(mutator);

}

typedef struct afl_scheduled_mutator afl_scheduled_afl_mutator_t;
typedef void (*mutator_func_type)(afl_mutator_t *, afl_raw_input_t *);

struct scheduled_mutator_functions {

  size_t (*schedule)(afl_scheduled_afl_mutator_t *);
  afl_ret_t (*add_mutator)(afl_scheduled_afl_mutator_t *, mutator_func_type);
  size_t (*iterations)(afl_scheduled_afl_mutator_t *);

};

struct afl_scheduled_mutator {

  afl_mutator_t      base;
  mutator_func_type *mutations;  // A ptr to an array of mutation operator
                                 // functions
  size_t                             mutators_count;
  struct scheduled_mutator_functions extra_funcs;
  size_t                             max_iterations;

};

/* TODO add implementation for the _schedule_ and _iterations_ functions, need a
 * random list element pop type implementation for this */
size_t    afl_iterations_default(afl_scheduled_afl_mutator_t *);
afl_ret_t afl_add_mutator_default(afl_scheduled_afl_mutator_t *, mutator_func_type);
size_t    afl_schedule_default(afl_scheduled_afl_mutator_t *);
size_t    afl_mutate_scheduled_mutator_default(afl_mutator_t *, afl_raw_input_t *);

afl_ret_t afl_scheduled_mutator_init(afl_scheduled_afl_mutator_t *, afl_stage_t *, size_t);
void      afl_scheduled_mutator_deinit(afl_scheduled_afl_mutator_t *);

static inline afl_scheduled_afl_mutator_t *afl_scheduled_mutator_new(afl_stage_t *stage, size_t max_iterations) {

  afl_scheduled_afl_mutator_t *sched_mut = calloc(1, sizeof(afl_scheduled_afl_mutator_t));

  if (afl_scheduled_mutator_init(sched_mut, stage, max_iterations) != AFL_RET_SUCCESS) {

    free(sched_mut);
    return NULL;

  }

  return sched_mut;

}

static inline void afl_scheduled_mutator_delete(afl_scheduled_afl_mutator_t *sched_mut) {

  afl_scheduled_mutator_deinit(sched_mut);
  free(sched_mut);

}

void mutator_flip_bit(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_flip_2_bits(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_flip_4_bits(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_flip_byte(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_flip_2_bytes(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_flip_4_bytes(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_random_byte_add_sub(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_random_byte(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_delete_bytes(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_clone_bytes(afl_mutator_t *mutator, afl_raw_input_t *input);
void mutator_splice(afl_mutator_t *mutator, afl_raw_input_t *input);

#endif

