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

#include "libmutator.h"
#include <stdlib.h>

#define ARITH_MAX 35

#define HAVOC_BLK_SMALL 32
#define HAVOC_BLK_MEDIUM 128
#define HAVOC_BLK_LARGE 1500
#define HAVOC_BLK_XL 32768

#define UNUSED(x) (void)(x)

void _afl_mutator_init_(mutator_t *mutator, stage_t *stage) {

  mutator->stage = stage;

  mutator->funcs.get_stage = get_mutator_stage_default;
  mutator->funcs.init = mutator_init_default;
  mutator->funcs.mutate = mutate_default;
  mutator->funcs.trim = trim_default;

}

void afl_mutator_deinit(mutator_t *mutator) {

  free(mutator);

}

stage_t *get_mutator_stage_default(mutator_t *mutator) {

  return mutator->stage;

}

void mutator_init_default(mutator_t *mutator) {

  UNUSED(mutator);

  /* TODO: Implementation */
  return;

};

size_t trim_default(mutator_t *mutator, u8 *mem, u8 *new_mem) {

  UNUSED(mutator);
  UNUSED(mem);
  UNUSED(new_mem);

  /* TODO: Implementation */
  return 0;

};

size_t mutate_default(mutator_t *mutator, raw_input_t *input, size_t size) {

  UNUSED(mutator);
  UNUSED(size);
  UNUSED(input);

  /* TODO: Implementation */
  return 0;

};

scheduled_mutator_t *afl_scheduled_mutator_init(stage_t *stage) {

  scheduled_mutator_t *sched_mut = ck_alloc(sizeof(scheduled_mutator_t));
  afl_mutator_init(&(sched_mut->base), stage);

  sched_mut->extra_funcs.add_mutator = add_mutator_default;
  sched_mut->extra_funcs.iterations = iterations_default;
  sched_mut->extra_funcs.schedule = schedule_default;

  return sched_mut;

}

void afl_scheduled_mutator_deinit(scheduled_mutator_t *mutator) {

  LIST_FOREACH_CLEAR(&(mutator->mutations), mutator_func_type, {});

  free(mutator);

}

void add_mutator_default(scheduled_mutator_t *mutator,
                         mutator_func_type    mutator_func) {

  list_append(&(mutator->mutations), mutator_func);

}

int iterations_default(scheduled_mutator_t *mutator) {

  UNUSED(mutator);

  /* TODO: Implementation */
  return 0;

};

int schedule_default(scheduled_mutator_t *mutator) {

  UNUSED(mutator);

  /* TODO: Implementation */
  return 0;

};

/* A few simple mutators that we use over in AFL++  */

static size_t choose_block_len(size_t limit) {

  size_t min_value, max_value;
  switch (rand_below(3)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;
    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;
    default:
      if (rand_below(10)) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) min_value = 1;

  return min_value +
         rand_below((max_value < limit ? max_value : limit) - min_value + 1);

}

void flip_bit_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  int bit = (rand()) % (input->len * 8);

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

void flip_2_bits_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  int bit = (rand()) % (size << 3);

  if ((size << 3) - bit > 2) { return; }

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

void flip_4_bits_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (size <= 0) { return; }

  int bit = (rand()) % (size << 3);

  if ((size << 3) - bit > 4) { return; }

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

void flip_byte_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (size <= 0) { return; }

  int byte = rand() % size;

  input->bytes[byte] ^= 0xff;

  return;

}

void flip_2_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (size < 2) { return; }

  int byte = rand_below(size - 1);

  ((u16 *)input->bytes)[byte] ^= 0xffff;

}

void flip_4_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (size < 4) { return; }

  int byte = rand_below(size - 3);

  ((u32 *)input->bytes)[byte] ^= 0xffffffff;

}

void random_byte_add_sub_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (size <= 0) { return; }

  size_t idx = rand_below(size);

  input->bytes[idx] -= 1 + rand_below(ARITH_MAX);
  input->bytes[idx] += 1 + rand_below(ARITH_MAX);

}

void random_byte_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;
  if (size <= 0) { return; }

  int idx = rand_below(size);
  input->bytes[idx] ^= 1 + rand_below(255);

}

void delete_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (size < 2) { return; }

  size_t del_len = choose_block_len(size - 1);
  size_t del_from = rand_below(size - del_len + 1);

  /* We delete the bytes and then update the new input length*/
  input->len = erase_bytes(input->bytes, size, del_from, del_len);

}

void clone_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  UNUSED(mutator);

  size_t size = input->len;

  if (!size) { return; }
  int actually_clone = rand_below(4);

  size_t clone_from, clone_to, clone_len;

  clone_to = rand_below(size);

  if (actually_clone) {

    clone_len = choose_block_len(size);
    clone_from = rand_below(size - clone_len + 1);

    input->bytes = insert_substring(
        input->bytes, size, input->bytes + clone_from, clone_len, clone_to);
    input->len += clone_len;

  } else {

    clone_len = choose_block_len(HAVOC_BLK_XL);

    insert_bytes(input->bytes, size, rand_below(255), clone_len, clone_to);

    input->len += clone_len;

  }

}

