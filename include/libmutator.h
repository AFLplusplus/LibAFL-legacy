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

#define MAX_MUTATORS_COUNT 10

#include "libinput.h"
#include "list.h"

// Mutator struct will have many internal functions like mutate, trimming etc.
// This is based on both the FFF prototype and the custom mutators that we have
// in AFL++ without the AFL++ specific parts

typedef struct mutator mutator_t;

struct mutator_functions {

  void (*init)(mutator_t *);  // Sort of like the afl_custom_init we have for
                              // custom mutators?

  size_t (*trim)(mutator_t *, u8 *,
                 u8 *);  // The params here are in_buf and out_buf.

  size_t (*mutate)(mutator_t *, raw_input_t *);  // Mutate function

  stage_t *(*get_stage)(mutator_t *);

};

struct mutator {

  stage_t *stage;

  struct mutator_functions funcs;

};

void     mutator_init_default(mutator_t *);
size_t   trim_default(mutator_t *, u8 *, u8 *);
stage_t *get_mutator_stage_default(mutator_t *);

afl_ret_t afl_mutator_init(mutator_t *, stage_t *);
void      afl_mutator_deinit(mutator_t *);

// A simple scheduled mutator based on the above mutator. Will act something
// similar to the havoc stage

static inline mutator_t *afl_mutator_create(stage_t *stage) {

  mutator_t *mutator = calloc(1, sizeof(mutator_t));
  if (!mutator) return NULL;
  if (afl_mutator_init(mutator, stage) == AFL_RET_SUCCESS) { 
    free(mutator);
    return NULL; }

  return mutator;

}

static inline void afl_mutator_delete(mutator_t *mutator) {

  afl_mutator_deinit(mutator);
  free(mutator);

}

typedef void (*mutator_func_type)(raw_input_t *);

typedef struct scheduled_mutator scheduled_mutator_t;

struct scheduled_mutator_functions {

  int (*schedule)(scheduled_mutator_t *);
  void (*add_mutator)(scheduled_mutator_t *, mutator_func_type);
  int (*iterations)(scheduled_mutator_t *);

};

struct scheduled_mutator {

  mutator_t base;
  mutator_func_type
      mutations[MAX_MUTATORS_COUNT];  // A ptr to an array of mutation operator
                                      // functions
  size_t                             mutators_count;
  struct scheduled_mutator_functions extra_funcs;
  size_t                             max_iterations;

};

/* TODO add implementation for the _schedule_ and _iterations_ functions, need a
 * random list element pop type implementation for this */
int    iterations_default(scheduled_mutator_t *);
void   add_mutator_default(scheduled_mutator_t *, mutator_func_type);
int    schedule_default(scheduled_mutator_t *);
size_t mutate_scheduled_mutator_default(mutator_t *, raw_input_t *);

afl_ret_t afl_scheduled_mutator_init(scheduled_mutator_t *, stage_t *, size_t);
void      afl_scheduled_mutator_deinit(scheduled_mutator_t *);

static inline scheduled_mutator_t *afl_scheduled_mutator_create(
    stage_t *stage, size_t max_iterations) {

  scheduled_mutator_t *sched_mut = calloc(1, sizeof(scheduled_mutator_t));

  if (afl_scheduled_mutator_init(sched_mut, stage, max_iterations) !=
      AFL_RET_SUCCESS) {

    return NULL;

  }

  return sched_mut;

}

static inline void afl_scheduled_mutator_delete(
    scheduled_mutator_t *sched_mut) {

  afl_scheduled_mutator_deinit(sched_mut);
  free(sched_mut);

}

void flip_bit_mutation(raw_input_t *input);
void flip_2_bits_mutation(raw_input_t *input);
void flip_4_bits_mutation(raw_input_t *input);
void flip_byte_mutation(raw_input_t *input);
void flip_2_bytes_mutation(raw_input_t *input);
void flip_4_bytes_mutation(raw_input_t *input);
void random_byte_add_sub_mutation(raw_input_t *input);
void random_byte_mutation(raw_input_t *input);
void delete_bytes_mutation(raw_input_t *input);
void clone_bytes_mutation(raw_input_t *input);

#endif

