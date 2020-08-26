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
static float __attribute__((hot)) coverage_fbck_is_interesting(feedback_t *feedback, executor_t * fsrv) {

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

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)obs_channel->shared_map.map;
  u64 *virgin = (u64 *)map_feedback->virgin_bits;

  u32 i = (obs_channel->shared_map.map_size >> 3);

#else

  u32 *current = (u32 *)obs_channel->map.;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = (obs_channel->shared_map.map_size >> 2);

#endif                                                     /* ^WORD_SIZE_64 */
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

        if (*virgin == 0xffffffffffffffff || (cur[0] && vir[0] == 0xff) ||
            (cur[1] && vir[1] == 0xff) || (cur[2] && vir[2] == 0xff) ||
            (cur[3] && vir[3] == 0xff) || (cur[4] && vir[4] == 0xff) ||
            (cur[5] && vir[5] == 0xff) || (cur[6] && vir[6] == 0xff) ||
            (cur[7] && vir[7] == 0xff)) {

          ret = 1.0;

        } else {

          ret = 0.5;

        }

#else

        if (*virgin == 0xffffffff || (cur[0] && vir[0] == 0xff) ||
            (cur[1] && vir[1] == 0xff) || (cur[2] && vir[2] == 0xff) ||
            (cur[3] && vir[3] == 0xff))
          ret = 1.0;
        else
          ret = 0.5;

#endif                                                     /* ^WORD_SIZE_64 */

      }

      *virgin &= ~*current;

    }

    ++current;
    ++virgin;

  }

  if (((ret == 0.5 ) || (ret == 1.0)) && feedback->queue) {

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
  return ret;

}

