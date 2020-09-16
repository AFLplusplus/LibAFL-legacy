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

#include "feedback.h"
#include "observer.h"
#include "aflpp.h"

afl_ret_t afl_feedback_init(afl_feedback_t *feedback, afl_queue_feedback_t *queue, size_t channel_id) {

  feedback->queue = queue;

  feedback->funcs.set_feedback_queue = afl_feedback_set_queue;
  feedback->funcs.get_feedback_queue = afl_feedback_get_queue;
  feedback->funcs.is_interesting = NULL;

  feedback->channel_id = channel_id;  // Channel id for the observation channel
                                      // this feedback is looking at

  return AFL_RET_SUCCESS;

}

void afl_feedback_deinit(afl_feedback_t *feedback) {

  if (feedback->metadata) {

    free(feedback->metadata);
    feedback->metadata = NULL;

  }

  /* Since feedback is deinitialized, we remove it's ptr from the feedback_queue
   */
  feedback->queue = NULL;

}

void afl_feedback_set_queue(afl_feedback_t *feedback, afl_queue_feedback_t *queue) {

  feedback->queue = queue;

  if (queue) { queue->feedback = feedback; }

}

afl_queue_feedback_t *afl_feedback_get_queue(afl_feedback_t *feedback) {

  return feedback->queue;

}

/* Map feedback. Can be easily used with a tracebits map similar to AFL++ */

afl_ret_t afl_feedback_cov_init(afl_feedback_cov_t *feedback, afl_queue_feedback_t *queue, size_t size,
                                size_t channel_id) {

  feedback->virgin_bits = calloc(1, size);
  if (!feedback->virgin_bits) { return AFL_RET_ALLOC; }
  memset(feedback->virgin_bits, 0xff, size);

  AFL_TRY(afl_feedback_init(&feedback->base, queue, channel_id), {

    free(feedback->virgin_bits);
    return err;

  });

  feedback->size = size;
  feedback->base.funcs.is_interesting = afl_feedback_cov_is_interesting;

  return AFL_RET_SUCCESS;

}

void afl_feedback_cov_deinit(afl_feedback_cov_t *feedback) {

  free(feedback->virgin_bits);
  feedback->virgin_bits = NULL;
  feedback->size = 0;
  afl_feedback_deinit(&feedback->base);

}

float __attribute__((hot)) afl_feedback_cov_is_interesting(afl_feedback_t *feedback, afl_executor_t *fsrv) {

  afl_feedback_cov_t *map_feedback = (afl_feedback_cov_t *)feedback;

  /* First get the observation channel */

  if (!feedback->channel) { feedback->channel = fsrv->funcs.observers_get(fsrv, feedback->channel_id); }

  afl_observer_covmap_t *obs_channel = (afl_observer_covmap_t *)feedback->channel;

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)obs_channel->shared_map.map;
  u64 *virgin = (u64 *)map_feedback->virgin_bits;

  u32 i = (obs_channel->shared_map.map_size >> 3);

#else

  u32 *current = (u32 *)obs_channel->shared_map.map;
  u32 *virgin = (u32 *)map_feedback->virgin_bits;

  u32 i = (obs_channel->shared_map.map_size >> 2);

#endif                                                                                             /* ^WORD_SIZE_64 */
  // the map size must be a minimum of 8 bytes.
  // for variable/dynamic map sizes this is ensured in the forkserver

  float ret = 0.0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    // the (*current) is unnecessary but speeds up the overall comparison
    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8 *cur = (u8 *)current;
        u8 *vir = (u8 *)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

        if (*virgin == 0xffffffffffffffff || (cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) || (cur[4] && vir[4] == 0xff) ||
            (cur[5] && vir[5] == 0xff) || (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) {

          ret = 1.0;

        } else {

          ret = 0.5;

        }

#else

        if (*virgin == 0xffffffff || (cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
          ret = 1.0;
        else
          ret = 0.5;

#endif                                                                                             /* ^WORD_SIZE_64 */

      }

      *virgin &= ~*current;

    }

    ++current;
    ++virgin;

  }

#ifdef DEBUG
  DBG("MAP: %p %lu ", obs_channel->shared_map.map, obs_channel->shared_map.map_size);
  for (u32 j = 0; j < obs_channel->shared_map.map_size; j++) {

    if (obs_channel->shared_map.map[j]) { printf("    %02x=%02x", j, obs_channel->shared_map.map[j]); }

  }

  printf(" ret=%f\n", ret);
#endif

  if (((ret == 0.5) || (ret == 1.0)) && feedback->queue) {

    afl_input_t *input = fsrv->current_input->funcs.copy(fsrv->current_input);

    if (!input) { FATAL("Error creating a copy of input"); }

    afl_entry_t *new_entry = afl_entry_new(input);
    feedback->queue->base.funcs.insert(&feedback->queue->base, new_entry);

    /* We broadcast a message when new entry found -- only if this is the fuzz
     * instance which found it!*/

    llmp_client_t * llmp_client = feedback->queue->base.engine->llmp_client;
    llmp_message_t *msg = llmp_client_alloc_next(llmp_client, sizeof(afl_entry_t));
    msg->tag = LLMP_TAG_NEW_QUEUE_ENTRY_V1;
    ((afl_entry_t *)msg->buf)[0] = *new_entry;
    llmp_client_send(llmp_client, msg);

    // Put the entry in the feedback queue and return 0.0 so that it isn't added
    // to the global queue too
    return 0.0;

  }

  return ret;

}

