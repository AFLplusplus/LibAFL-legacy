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

#ifndef LIBFEEDBACK_H
#define LIBFEEDBACK_H

#include "queue.h"
#include "observer.h"

typedef struct feedback afl_feedback_t;

struct feedback_functions {

  float (*is_interesting)(afl_feedback_t *, afl_executor_t *);
  void (*set_feedback_queue)(afl_feedback_t *, afl_feedback_queue_t *);
  afl_feedback_queue_t *(*get_feedback_queue)(afl_feedback_t *);

};

struct feedback {

  afl_feedback_queue_t *queue;

  struct afl_feedback_metadata *metadata; /* We can have a void pointer for the
                                         struct here. What do you guys say? */

  struct feedback_functions funcs;
  size_t                    channel_id;  // ID of the observation channel this feedback is watching
  afl_observer_t *          channel;     // This array holds the observation channels the feedback is
                                         // looking at. Specific fpr each feedback. btw, Better name for
                                         // this? :p

};

typedef struct afl_feedback_metadata {

  // This struct is more dependent on user's implementation.
  afl_feedback_t *feedback;

} afl_feedback_metadata_t;

// Default implementation of the vtables functions

void                  afl_set_feedback_queue_default(afl_feedback_t *, afl_feedback_queue_t *);
afl_feedback_queue_t *afl_get_feedback_queue_default(afl_feedback_t *);

// "Constructors" and "destructors" for the feedback
void      afl_feedback_deinit(afl_feedback_t *);
afl_ret_t afl_feedback_init(afl_feedback_t *, afl_feedback_queue_t *, size_t channel_id);

static inline afl_feedback_t *afl_feedback_new(afl_feedback_queue_t *queue, size_t channel_id) {

  afl_feedback_t *feedback = calloc(1, sizeof(afl_feedback_t));
  if (!feedback) return NULL;
  if (afl_feedback_init(feedback, queue, channel_id) != AFL_RET_SUCCESS) {

    free(feedback);
    return NULL;

  }

  return feedback;

}

static inline void afl_feedback_delete(afl_feedback_t *feedback) {

  afl_feedback_deinit(feedback);
  free(feedback);

}

/* Simple MaximizeMapFeedback implementation */

#define MAP_CHANNEL_ID 0x1

typedef struct maximize_map_feedback {

  afl_feedback_t base;

  u8 *   virgin_bits;
  size_t size;

} afl_maximize_map_feedback_t;

afl_maximize_map_feedback_t *map_feedback_init(afl_feedback_queue_t *queue, size_t size, size_t channel_id);

float map_fbck_is_interesting(afl_feedback_t *feedback, afl_executor_t *fsrv);

#endif

