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

typedef struct feedback feedback_t;

struct feedback_functions {

  float (*is_interesting)(feedback_t *, executor_t *);
  void (*set_feedback_queue)(feedback_t *, feedback_queue_t *);
  feedback_queue_t *(*get_feedback_queue)(feedback_t *);

};

struct feedback {

  feedback_queue_t *queue;

  struct feedback_metadata *metadata; /* We can have a void pointer for the
                                         struct here. What do you guys say? */

  struct feedback_functions funcs;
  int                       observation_idx;

};

typedef struct feedback_metadata {

  // This struct is more dependent on user's implementation.
  feedback_t *feedback;

} feedback_metadata_t;

// Default implementation of the vtables functions

/*TODO: Can we have a similiar implementation for the is_interesting function?*/
void afl_set_feedback_queue_default(feedback_t *, feedback_queue_t *);
feedback_queue_t *afl_get_feedback_queue_default(feedback_t *);

// "Constructors" and "destructors" for the feedback
void      afl_feedback_deinit(feedback_t *);
afl_ret_t afl_feedback_init(feedback_t *, feedback_queue_t *);

static inline feedback_t *afl_feedback_create(feedback_queue_t *queue) {

  feedback_t *feedback = calloc(1, sizeof(feedback_t));
  if (!feedback) return NULL;
  if (afl_feedback_init(feedback, queue) != AFL_RET_SUCCESS) {

    free(feedback);
    return NULL;

  }

  return feedback;

}

static inline void afl_feedback_delete(feedback_t *feedback) {

  afl_feedback_deinit(feedback);
  free(feedback);

}

/* TODO: Add MaximizeMapFeedback implementation */

#endif

