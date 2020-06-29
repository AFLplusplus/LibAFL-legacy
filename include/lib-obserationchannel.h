#include "lib-common.h"

typedef struct observation_channel {

  struct observation_channel_operations *operations;

} observation_channel_t;

// vtable for the observation channel

struct observation_channel_operations {

  void (*flush)(observation_channel_t *);
  void (*reset)(observation_channel_t *);
  void (*post_exec)(observation_channel_t *);

};

// Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.

observation_channel_t *afl_obs_channel_init();
void                   afl_obs_channel_deinit();

typedef struct map_based_channel {

  observation_channel_t super;  // Base observation channel "class"

  afl_sharedmem_t *shared_map;

  struct map_based_channel_operations *extra_ops;

} map_based_channel_t;

struct map_based_channel_operations {

  u8 *(*get_trace_bits)(map_based_channel_t *);
  size_t (*get_map_size)(map_based_channel_t *);

};

u8 *   get_trace_bits(map_based_channel_t *obs_channel);
size_t get_size(map_based_channel_t *obs_channel);

// Functions to initialize and delete a map based observation channel

map_based_channel_t *afl_map_channel_init(size_t);
void                 afl_map_channel_deinit(map_based_channel_t *);

