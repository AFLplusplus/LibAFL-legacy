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

#define AFL_FEEDBACK_TAG_BASE (0xFEEDB43E)
#define AFL_FEEDBACK_TAG_COV (0xFEEDC0F8)

typedef struct afl_queue_feedback afl_queue_feedback_t;
typedef struct afl_feedback       afl_feedback_t;

struct afl_feedback_funcs {

  float (*is_interesting)(afl_feedback_t *, afl_executor_t *);
  void (*set_feedback_queue)(afl_feedback_t *, afl_queue_feedback_t *);
  afl_queue_feedback_t *(*get_feedback_queue)(afl_feedback_t *);

};

struct afl_feedback {

  afl_queue_feedback_t *queue;

  struct afl_feedback_funcs funcs;
  u32                       tag;

};

// Default implementation of the functions

void                  afl_feedback_set_queue(afl_feedback_t *, afl_queue_feedback_t *);
afl_queue_feedback_t *afl_feedback_get_queue(afl_feedback_t *);

// "Constructors" and "destructors" for the feedback
void      afl_feedback_deinit(afl_feedback_t *);
afl_ret_t afl_feedback_init(afl_feedback_t *, afl_queue_feedback_t *queue);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_feedback, AFL_DECL_PARAMS(afl_queue_feedback_t *queue), AFL_CALL_PARAMS(queue))

/* Simple MaximizeMapFeedback implementation */

/* Coverage Feedback */
typedef struct afl_feedback_cov {

  afl_feedback_t base;

  /* This array holds the coveragemap observation channels the feedback is looking at */
  afl_observer_covmap_t *observer_cov;

  u8 *   virgin_bits;
  size_t size;

} afl_feedback_cov_t;

afl_ret_t afl_feedback_cov_init(afl_feedback_cov_t *feedback, afl_queue_feedback_t *queue,
                                afl_observer_covmap_t *map_observer);
void      afl_feedback_cov_deinit(afl_feedback_cov_t *feedback);

AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_feedback_cov,
                                   AFL_DECL_PARAMS(afl_queue_feedback_t *queue, afl_observer_covmap_t *map_observer),
                                   AFL_CALL_PARAMS(queue, map_observer))

/* Set virgin bits according to the map passed into the func */
afl_ret_t afl_feedback_cov_set_virgin_bits(afl_feedback_cov_t *feedback, u8 *virgin_bits_copy_from, size_t size);

/* Returns the "interestingness" of the current feedback */
float afl_feedback_cov_is_interesting(afl_feedback_t *feedback, afl_executor_t *fsrv);

#endif

