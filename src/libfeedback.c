#include "libfeedback.h"

feedback_t *afl_feedback_init() {

  feedback_t *feedback = ck_alloc(sizeof(feedback_t));
  feedback->operations = ck_alloc(sizeof(struct feedback_operations));

  feedback->operations->set_feedback_queue = set_feedback_queue;
  feedback->operations->get_feedback_queue = get_feedback_queue;

  return feedback;

}

void afl_feedback_deinit(feedback_t *feedback) {

  ck_free(feedback->operations);
  if (feedback->metadata) ck_free(feedback->metadata);

  ck_free(feedback);

}

void set_feedback_queue(feedback_t *feedback, feedback_queue_t *queue) {

  feedback->queue = queue;

}

feedback_queue_t *get_feedback_queue(feedback_t *feedback) {

  return feedback->queue;

}

