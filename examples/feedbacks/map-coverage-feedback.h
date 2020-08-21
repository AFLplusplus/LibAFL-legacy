/* We implement a simple map maximising feedback here. */

#include "aflpp.h"

typedef struct maximize_map_feedback {

  feedback_t base;

  u8 *   virgin_bits;
  size_t size;

} maximize_map_feedback_t;

#define MAP_CHANNEL_ID 0x1


static maximize_map_feedback_t *map_feedback_init(feedback_queue_t *queue,
                                                  size_t            size);
static float coverage_fbck_is_interesting(feedback_t *feedback,
                                          executor_t *fsrv);

/* Init function for the feedback */
static maximize_map_feedback_t *map_feedback_init(feedback_queue_t *queue,
                                                  size_t            size) {

  maximize_map_feedback_t *feedback =
      calloc(1, sizeof(maximize_map_feedback_t));
  if (!feedback) { return NULL; }
  afl_feedback_init(&feedback->base, queue);

  feedback->base.funcs.is_interesting = coverage_fbck_is_interesting;

  feedback->virgin_bits = calloc(1, size);
  if (!feedback->virgin_bits) {

    free(feedback);
    return NULL;

  }

  feedback->size = size;

  return feedback;

}

/* We'll implement a simple is_interesting function for the feedback, which
 * checks if new tuples have been hit in the map */
static float coverage_fbck_is_interesting(feedback_t *feedback,
                                          executor_t *fsrv) {

  maximize_map_feedback_t *map_feedback = (maximize_map_feedback_t *)feedback;

  /* First get the observation channel */

  if (feedback->observation_idx == -1) {
    for (size_t i = 0; i < fsrv->observors_num; ++i) {
      if (fsrv->observors[i]->channel_id == MAP_CHANNEL_ID) {
        feedback->observation_idx = i;
        break;
      }
    }
  }

  map_based_channel_t *obs_channel =
      (map_based_channel_t *)fsrv->funcs.get_observation_channels(fsrv, feedback->observation_idx);
  bool found = false;

  u8 *   trace_bits = obs_channel->shared_map.map;
  size_t map_size = obs_channel->shared_map.map_size;

  for (size_t i = 0; i < map_size; ++i) {

    if (trace_bits[i] > map_feedback->virgin_bits[i]) { found = true; }

  }

  if (found && feedback->queue) {

    raw_input_t *input = fsrv->current_input->funcs.copy(fsrv->current_input);

    if (!input) { FATAL("Error creating a copy of input"); }

    queue_entry_t *new_entry = afl_queue_entry_create(input);
    // An incompatible ptr type warning has been suppresed here. We pass the
    // feedback queue to the add_to_queue rather than the base_queue
    feedback->queue->base.funcs.add_to_queue(&feedback->queue->base, new_entry);

    // Put the entry in the feedback queue and return 0.0 so that it isn't added
    // to the global queue too
    return 0.0;

  }

  return found ? 1.0 : 0.0;

}
