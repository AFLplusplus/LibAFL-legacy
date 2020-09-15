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
#include "config.h"
#include "debug.h"

afl_ret_t afl_mutator_init(afl_mutator_t *mutator, afl_engine_t *engine) {

  mutator->engine = engine;
  return AFL_RET_SUCCESS;

}

void afl_mutator_deinit(afl_mutator_t *mutator) {

  mutator->engine = NULL;

}

afl_ret_t afl_mutator_scheduled_init(afl_mutator_scheduled_t *sched_mut, afl_engine_t *engine, size_t max_iterations) {

  AFL_TRY(afl_mutator_init(&(sched_mut->base), engine), { return err; });

  sched_mut->base.funcs.mutate = afl_mutate_scheduled_mutator;
  sched_mut->funcs.add_func = afl_mutator_add_func;
  sched_mut->funcs.get_iters = afl_iterations;
  sched_mut->funcs.schedule = afl_schedule;

  sched_mut->max_iterations = (max_iterations > 0) ? max_iterations : 7;
  return AFL_RET_SUCCESS;

}

void afl_mutator_scheduled_deinit(afl_mutator_scheduled_t *sched_mut) {

  size_t i;
  afl_mutator_deinit(&(sched_mut->base));
  sched_mut->max_iterations = 0;

  for (i = 0; i < sched_mut->mutators_count; ++i) {

    sched_mut->mutations[i] = NULL;

  }

  afl_free(sched_mut->mutations);
  sched_mut->mutations = NULL;

  sched_mut->mutators_count = 0;

}

afl_ret_t afl_mutator_add_func(afl_mutator_scheduled_t *mutator, afl_mutator_func mutator_func) {

  mutator->mutators_count++;
  mutator->mutations = afl_realloc(mutator->mutations, mutator->mutators_count * sizeof(afl_mutator_func));
  if (!mutator->mutations) {

    mutator->mutators_count = 0;
    return AFL_RET_ALLOC;

  }

  mutator->mutations[mutator->mutators_count - 1] = mutator_func;
  return AFL_RET_SUCCESS;

}

size_t afl_iterations(afl_mutator_scheduled_t *mutator) {

  return 1 << (1 + afl_rand_below(&mutator->base.engine->rand, mutator->max_iterations));

}

size_t afl_schedule(afl_mutator_scheduled_t *mutator) {

  return afl_rand_below(&mutator->base.engine->rand, mutator->mutators_count);

}

size_t afl_mutate_scheduled_mutator(afl_mutator_t *mutator, afl_input_t *input) {

  // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
  afl_mutator_scheduled_t *scheduled_mutator = (afl_mutator_scheduled_t *)mutator;
  size_t                   i;
  for (i = 0; i < scheduled_mutator->funcs.get_iters(scheduled_mutator); ++i) {

    scheduled_mutator->mutations[scheduled_mutator->funcs.schedule(scheduled_mutator)](&scheduled_mutator->base, input);

  }

  return 0;

}

/* A few simple mutators that we use over in AFL++ in the havoc and
 * deterministic modes*/

static size_t choose_block_len(afl_rand_t *rand, size_t limit) {

  size_t min_value, max_value;
  switch (afl_rand_below(rand, 3)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;
    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;
    default:
      if (afl_rand_below(rand, 10)) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return afl_rand_between(rand, min_value, MIN(max_value, limit));

}

void afl_mutfunc_flip_bit(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;
  int         bit = afl_rand_below(rand, input->len * 8 - 1) + 1;

  input->bytes[(bit >> 3)] ^= (1 << ((bit - 1) % 8));

}

void afl_mutfunc_flip_2_bits(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;
  size_t      size = input->len;

  int bit = afl_rand_below(rand, (size * 8) - 1) + 1;

  if ((size << 3) - bit < 2) { return; }

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

void afl_mutfunc_flip_4_bits(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (size <= 0) { return; }

  int bit = afl_rand_below(rand, (size << 3) - 1) + 1;

  if ((size << 3) - bit < 4) { return; }

  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));
  bit++;
  input->bytes[bit >> 3] ^= (1 << ((bit - 1) % 8));

}

inline void afl_mutfunc_flip_byte(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (size <= 0) { return; }

  int byte = afl_rand_below(rand, size);

  input->bytes[byte] ^= 0xff;

  return;

}

inline void afl_mutfunc_flip_2_bytes(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (size < 2) { return; }

  int byte = afl_rand_below(rand, size - 1);

  input->bytes[byte] ^= 0xff;
  input->bytes[byte + 1] ^= 0xff;

}

inline void afl_mutfunc_flip_4_bytes(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (size < 4) { return; }

  int byte = afl_rand_below(rand, size - 3);

  if (byte == -1) { return; }

  input->bytes[byte] ^= 0xff;
  input->bytes[byte + 1] ^= 0xff;
  input->bytes[byte + 2] ^= 0xff;
  input->bytes[byte + 3] ^= 0xff;

}

inline void afl_mutfunc_random_byte_add_sub(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (size <= 0) { return; }

  size_t idx = afl_rand_below(rand, size);

  input->bytes[idx] -= 1 + (u8)afl_rand_below(rand, ARITH_MAX);
  input->bytes[idx] += 1 + (u8)afl_rand_below(rand, ARITH_MAX);

}

inline void afl_mutfunc_random_byte(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;
  if (size <= 0) { return; }

  int idx = afl_rand_below(rand, size);
  input->bytes[idx] ^= 1 + (u8)afl_rand_below(rand, 255);

}

inline void afl_mutfunc_delete_bytes(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (size < 2) { return; }

  size_t del_len = choose_block_len(rand, size - 1);
  size_t del_from = afl_rand_below(rand, size - del_len + 1);

  /* We delete the bytes and then update the new input length*/
  input->len = afl_erase_bytes(input->bytes, size, del_from, del_len);

}

void afl_mutfunc_clone_bytes(afl_mutator_t *mutator, afl_input_t *input) {

  afl_rand_t *rand = &mutator->engine->rand;

  size_t size = input->len;

  if (!size) { return; }
  int actually_clone = afl_rand_below(rand, 4);

  size_t clone_from, clone_to, clone_len;

  clone_to = afl_rand_below(rand, size);

  u8 *current_bytes = input->bytes;

  if (actually_clone) {

    clone_len = choose_block_len(rand, size);
    clone_from = afl_rand_below(rand, size - clone_len + 1);

    input->bytes = afl_insert_substring(input->bytes, size, input->bytes + clone_from, clone_len, clone_to);
    input->len += clone_len;

  } else {

    clone_len = choose_block_len(rand, HAVOC_BLK_XL);

    input->bytes = afl_insert_bytes(input->bytes, size, afl_rand_below(rand, 255), clone_len, clone_to);

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

void afl_mutfunc_splice(afl_mutator_t *mutator, afl_input_t *input) {

  /* Let's grab the engine for random num generation and queue */

  afl_engine_t *      engine = mutator->engine;
  afl_queue_global_t *global_queue = engine->global_queue;

  afl_input_t *splice_input = NULL;

  s32 f_diff = 0;
  s32 l_diff = 0;

  int counter = 0;

  do {

    size_t random_queue_idx =
        afl_rand_below(&engine->rand, global_queue->feedback_queues_count + 1);  // +1 so that we can also grab a queue
                                                                                 // entry from the global_queue

    if (random_queue_idx < global_queue->feedback_queues_count) {

      // Grab a random entry from the random feedback queue
      afl_queue_feedback_t *random_fbck_queue = global_queue->feedback_queues[random_queue_idx];
      splice_input =
          (random_fbck_queue->base.entries_count > 0)
              ? random_fbck_queue->base.entries[afl_rand_below(&engine->rand, random_fbck_queue->base.entries_count)]
                    ->input
              : NULL;

      if (splice_input && !splice_input->bytes) { splice_input = NULL; }

    } else {

      // Grab a random entry from the global queue
      splice_input =
          (global_queue->base.entries_count > 0)
              ? global_queue->base.entries[afl_rand_below(&engine->rand, global_queue->base.entries_count)]->input
              : NULL;
      if (splice_input && !splice_input->bytes) { splice_input = NULL; }

    }

    // Counter basically stops it from infinite loop in case of empty queue
    if (counter++ > 20) { return; }

    if (!splice_input) { continue; }

    locate_diffs(input->bytes, splice_input->bytes, MIN((s64)input->len, (s64)splice_input->len), &f_diff, &l_diff);

  } while (f_diff < 0 || l_diff < 2 || f_diff == l_diff);

  /* Split somewhere between the first and last differing byte. */

  u32 split_at = f_diff + afl_rand_below(&engine->rand, l_diff - f_diff);

  /* Do the thing. */

  input->len = splice_input->len;

  input->bytes = realloc(input->bytes, input->len);
  memcpy(input->bytes + split_at, splice_input->bytes + split_at, splice_input->len - split_at);

}

afl_ret_t afl_mutator_scheduled_add_havoc_funcs(afl_mutator_scheduled_t *mutator) {

  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_flip_byte), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_flip_2_bytes), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_flip_4_bytes), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_delete_bytes), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_clone_bytes), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_flip_bit), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_flip_2_bits), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_flip_4_bits), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_random_byte_add_sub), { return err; });
  AFL_TRY(mutator->funcs.add_func(mutator, afl_mutfunc_random_byte), { return err; });

  return AFL_RET_SUCCESS;

}

