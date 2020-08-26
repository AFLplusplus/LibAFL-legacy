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

#include <stdlib.h>

#include "mutator.h"
#include "engine.h"
#include "stage.h"
#include "alloc-inl.h"

#define ARITH_MAX 35

#define HAVOC_BLK_SMALL 32
#define HAVOC_BLK_MEDIUM 128
#define HAVOC_BLK_LARGE 1500
#define HAVOC_BLK_XL 32768

afl_ret_t afl_mutator_init(mutator_t *mutator, stage_t *stage) {

  mutator->stage = stage;

  return AFL_RET_SUCCESS;

}

void afl_mutator_deinit(mutator_t *mutator) {

  mutator->stage = NULL;

}

stage_t *afl_get_mutator_stage_default(mutator_t *mutator) {

  return mutator->stage;

}

afl_ret_t afl_scheduled_mutator_init(scheduled_mutator_t *sched_mut,
                                     stage_t *stage, size_t max_iterations) {

  if (afl_mutator_init(&(sched_mut->base), stage) != AFL_RET_SUCCESS) {

    return AFL_RET_ERROR_INITIALIZE;

  }

  sched_mut->base.funcs.mutate = afl_mutate_scheduled_mutator_default;
  sched_mut->extra_funcs.add_mutator = afl_add_mutator_default;
  sched_mut->extra_funcs.iterations = afl_iterations_default;
  sched_mut->extra_funcs.schedule = afl_schedule_default;

  sched_mut->max_iterations = (max_iterations > 0) ? max_iterations : 7;
  return AFL_RET_SUCCESS;

}

void afl_scheduled_mutator_deinit(scheduled_mutator_t *sched_mut) {

  size_t i;
  afl_mutator_deinit(&(sched_mut->base));
  sched_mut->max_iterations = 0;

  for (i = 0; i < sched_mut->mutators_count; ++i) {

    sched_mut->mutations[i] = NULL;

  }

  sched_mut->mutators_count = 0;

}

void afl_add_mutator_default(scheduled_mutator_t *mutator,
                             mutator_func_type    mutator_func) {

  mutator->mutations[mutator->mutators_count] = mutator_func;
  mutator->mutators_count++;

}

size_t afl_iterations_default(scheduled_mutator_t *mutator) {

  return 1 << (1 + afl_rand_below(&mutator->base.stage->engine->rnd,
                                  mutator->max_iterations));

}

size_t afl_schedule_default(scheduled_mutator_t *mutator) {

  return afl_rand_below(&mutator->base.stage->engine->rnd,
                        mutator->mutators_count);

}

size_t afl_mutate_scheduled_mutator_default(mutator_t *  mutator,
                                            raw_input_t *input) {

  // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
  scheduled_mutator_t *scheduled_mutator = (scheduled_mutator_t *)mutator;
  size_t               i;
  for (i = 0; i < scheduled_mutator->extra_funcs.iterations(scheduled_mutator);
       ++i) {

    scheduled_mutator
        ->mutations[scheduled_mutator->extra_funcs.schedule(scheduled_mutator)](
            &scheduled_mutator->base, input);

  }

  return 0;

}

/* A few simple mutators that we use over in AFL++ in the havoc and
 * deterministic modes*/

static size_t choose_block_len(afl_rand_t *rnd, size_t limit) {

  size_t min_value, max_value;
  switch (afl_rand_below(rnd, 3)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;
    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;
    default:
      if (afl_rand_below(rnd, 10)) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + afl_rand_below(rnd, MIN(max_value, limit)) - min_value + 1;

}

inline void flip_bit_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;
  int         bit = afl_rand_below(rnd, input->len * 8 - 1) + 1;

  input->bytes[(bit >> 3)] ^= (1 << ((bit - 1) % 8));

}

inline void flip_2_bits_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;
  size_t      size = input->len;

  int bit = afl_rand_below(rnd, (size * 8) - 1) + 1;

  if ((size << 3) - bit < 2) { return; }

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

inline void flip_4_bits_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (size <= 0) { return; }

  int bit = afl_rand_below(rnd, size << 3);

  if ((size << 3) - bit < 4) { return; }

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

inline void flip_byte_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (size <= 0) { return; }

  int byte = afl_rand_below(rnd, size);

  input->bytes[byte] ^= 0xff;

  return;

}

inline void flip_2_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (size < 2) { return; }

  int byte = afl_rand_below(rnd, size - 1);

  input->bytes[byte] ^= 0xff;
  input->bytes[byte + 1] ^= 0xff;

}

inline void flip_4_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (size < 4) { return; }

  int byte = afl_rand_below(rnd, size - 3);

  if (byte == -1) { return; }

  input->bytes[byte] ^= 0xff;
  input->bytes[byte + 1] ^= 0xff;
  input->bytes[byte + 2] ^= 0xff;
  input->bytes[byte + 3] ^= 0xff;

}

inline void random_byte_add_sub_mutation(mutator_t *  mutator,
                                         raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (size <= 0) { return; }

  size_t idx = afl_rand_below(rnd, size);

  input->bytes[idx] -= 1 + (u8)afl_rand_below(rnd, ARITH_MAX);
  input->bytes[idx] += 1 + (u8)afl_rand_below(rnd, ARITH_MAX);

}

inline void random_byte_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;
  if (size <= 0) { return; }

  int idx = afl_rand_below(rnd, size);
  input->bytes[idx] ^= 1 + (u8)afl_rand_below(rnd, 255);

}

inline void delete_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (size < 2) { return; }

  size_t del_len = choose_block_len(rnd, size - 1);
  size_t del_from = afl_rand_below(rnd, size - del_len + 1);

  /* We delete the bytes and then update the new input length*/
  input->len = afl_erase_bytes(input->bytes, size, del_from, del_len);

}

inline void clone_bytes_mutation(mutator_t *mutator, raw_input_t *input) {

  afl_rand_t *rnd = &mutator->stage->engine->rnd;

  size_t size = input->len;

  if (!size) { return; }
  int actually_clone = afl_rand_below(rnd, 4);

  size_t clone_from, clone_to, clone_len;

  clone_to = afl_rand_below(rnd, size);

  u8 *current_bytes = input->bytes;

  if (actually_clone) {

    clone_len = choose_block_len(rnd, size);
    clone_from = afl_rand_below(rnd, size - clone_len + 1);

    input->bytes = afl_insert_substring(
        input->bytes, size, input->bytes + clone_from, clone_len, clone_to);
    input->len += clone_len;

  } else {

    clone_len = choose_block_len(rnd, HAVOC_BLK_XL);

    input->bytes = afl_insert_bytes(
        input->bytes, size, afl_rand_below(rnd, 255), clone_len, clone_to);

    input->len += clone_len;

  }

  free(current_bytes);

}

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) { f_loc = pos; }
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

void splicing_mutation(mutator_t *mutator, raw_input_t *input) {

  /* Let's grab the engine for random num generation and queue */

  engine_t *      engine = mutator->stage->engine;
  global_queue_t *global_queue = engine->global_queue;

  raw_input_t *splice_input = NULL;
  s32          f_diff, l_diff;

  int counter = 0;

retry_splicing:

  do {

    size_t random_queue_idx = afl_rand_below(
        &engine->rnd, global_queue->feedback_queues_num +
                          1);  // +1 so that we can also grab a queue entry from
                               // the global_queue

    if (random_queue_idx < global_queue->feedback_queues_num) {

      // Grab a random entry from the random feedback queue
      feedback_queue_t *random_fbck_queue =
          global_queue->feedback_queues[random_queue_idx];
      splice_input = (random_fbck_queue->base.size > 0)
                         ? random_fbck_queue->base
                               .queue_entries[afl_rand_below(
                                   &engine->rnd, random_fbck_queue->base.size)]
                               ->input
                         : NULL;

      if (splice_input && !splice_input->bytes) { splice_input = NULL; }

    } else {

      // Grab a random entry from the global queue
      splice_input = (global_queue->base.size > 0)
                         ? global_queue->base
                               .queue_entries[afl_rand_below(
                                   &engine->rnd, global_queue->base.size)]
                               ->input
                         : NULL;
      if (splice_input && !splice_input->bytes) { splice_input = NULL; }

    }

    // Counter basically stops it from infinite loop in case of empty queue
    if (counter++ > 20) { return; }

  } while (splice_input == NULL);

  locate_diffs(input->bytes, splice_input->bytes,
               MIN((s64)input->len, (s64)splice_input->len), &f_diff, &l_diff);

  if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) { goto retry_splicing; }

  /* Split somewhere between the first and last differing byte. */

  u32 split_at = f_diff + afl_rand_below(&engine->rnd, l_diff - f_diff);

  /* Do the thing. */

  input->len = splice_input->len;

  input->bytes = realloc(input->bytes, splice_input->len);
  memcpy(input->bytes + split_at, splice_input->bytes + split_at,
         splice_input->len - split_at);

  input->len = splice_input->len;

}

