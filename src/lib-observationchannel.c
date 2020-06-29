#include "lib-obserationchannel.h"

observation_channel_t *afl_obs_channel_init(void) {

  observation_channel_t *channel = ck_alloc(sizeof(observation_channel_t));

  channel->operations = ck_alloc(sizeof(struct observation_channel_operations));

  return channel;

}

void afl_obs_channel_deinit(observation_channel_t *channel) {

  ck_free(channel->operations);

  ck_free(channel);

}

map_based_channel_t *afl_map_channel_init(size_t map_size) {

  map_based_channel_t *map_channel = ck_alloc(sizeof(map_based_channel_t));

  map_channel->super = *(afl_obs_channel_init());

  map_channel->shared_map = ck_alloc(sizeof(afl_sharedmem_t));
  afl_sharedmem_init(map_channel->shared_map, map_size);

  map_channel->extra_ops =
      ck_alloc(sizeof(struct map_based_channel_operations));
  map_channel->extra_ops->get_map_size = get_size;
  map_channel->extra_ops->get_trace_bits = get_trace_bits;

  return map_channel;

}

void afl_map_channel_deinit(map_based_channel_t *map_channel) {

  ck_free(map_channel->super.operations);
  ck_free(map_channel->extra_ops);
  afl_sharedmem_deinit(map_channel->shared_map);

  ck_free(map_channel);

}

u8 *get_trace_bits(map_based_channel_t *obs_channel) {

  return obs_channel->shared_map->map;

}

size_t get_size(map_based_channel_t *obs_channel) {

  return obs_channel->shared_map->map_size;

}

