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

#ifndef LIBAFL_MUTATOR_HAVOC_H
#define LIBAFL_MUTATOR_HAVOC_H

#include "object.h"
#include "error.h"

#include "mutator/scheduled.h"
#include "corpus/corpus.h"

extern struct afl_scheduled_mutator_vtable afl_havoc_mutator_vtable_instance;

typedef struct afl_havoc_mutator afl_havoc_mutator_t;

struct afl_havoc_mutator {

  INHERITS(afl_scheduled_mutator)

  afl_corpus_t* corpus;

};

/*
  Initialize an empty, just allocated, afl_havoc_mutator_t object.
*/
afl_ret_t afl_havoc_mutator_init(afl_havoc_mutator_t *);

/*
  Destroy the context of an afl_havoc_mutator_t.
*/
static inline void afl_havoc_mutator_deinit(afl_havoc_mutator_t * self) {

  afl_scheduled_mutator_deinit((afl_scheduled_mutator_t*)self);

}

void afl_mutation_flip_bit(afl_mutator_t *, afl_input_t *);
void afl_mutation_flip_2_bits(afl_mutator_t *, afl_input_t *);
void afl_mutation_flip_4_bits(afl_mutator_t *, afl_input_t *);
void afl_mutation_flip_byte(afl_mutator_t *, afl_input_t *);
void afl_mutation_flip_2_bytes(afl_mutator_t *, afl_input_t *);
void afl_mutation_flip_4_bytes(afl_mutator_t *, afl_input_t *);
void afl_mutation_random_byte_add_sub(afl_mutator_t *, afl_input_t *);
void afl_mutation_random_byte(afl_mutator_t *, afl_input_t *);
void afl_mutation_delete_bytes(afl_mutator_t *, afl_input_t *);
void afl_mutation_clone_bytes(afl_mutator_t *, afl_input_t *);
void afl_mutation_splice(afl_mutator_t *, afl_input_t *);

#endif

