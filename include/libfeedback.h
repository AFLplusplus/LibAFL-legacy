#include "lib-common.h"
#include "libqueue.h"
#include "libaflpp.h"

typedef struct feedback {

  feedback_queue_t *queue;

  struct feedback_metadata *metadata; /* We can have a void pointer for the
                                         struct here. What do you guys say? */

  struct feedback_operations *operations;

} feedback_t;

struct feedback_operations {

  float (*is_interesting)(feedback_t *, afl_executor_t *);
  void (*set_feedback_queue)(feedback_t *, feedback_queue_t *);
  feedback_queue_t *(*get_feedback_queue)(feedback_t *)

};

typedef struct feedback_metadata {

  // This struct is more dependent on user's implementation.
  feedback_t *feedback;

} feedback_metadata_t;

// Default implementation of the vtables functions

/*TODO: Can we have a similiar implementation for the is_interesting function?*/
void              set_feedback_queue(feedback_t *, feedback_queue_t *);
feedback_queue_t *get_feedback_queue(feedback_t *);

// "Constructors" and "destructors" for the feedback
void        afl_feedback_deinit(feedback_t *);
feedback_t *afl_feedback_init();

/* TODO: Add MaximizeMapFeedback implementation */

