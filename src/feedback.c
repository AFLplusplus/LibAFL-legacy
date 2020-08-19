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

afl_ret_t afl_feedback_init(feedback_t *feedback, feedback_queue_t *queue) {

  feedback->queue = queue;

  feedback->funcs.set_feedback_queue = afl_set_feedback_queue_default;
  feedback->funcs.get_feedback_queue = afl_get_feedback_queue_default;

  feedback->observation_idx = -1;  // Initialize this to a negative index

  return AFL_RET_SUCCESS;

}

void afl_feedback_deinit(feedback_t *feedback) {

  if (feedback->metadata) {

    free(feedback->metadata);
    feedback->metadata = NULL;

  }

  /* Since feedback is deinitialized, we remove it's ptr from the feedback_queue
   */
  feedback->queue = NULL;

}

void afl_set_feedback_queue_default(feedback_t *      feedback,
                                    feedback_queue_t *queue) {

  feedback->queue = queue;

}

feedback_queue_t *afl_get_feedback_queue_default(feedback_t *feedback) {

  return feedback->queue;

}

