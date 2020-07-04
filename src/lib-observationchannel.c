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
  map_channel->extra_ops->get_map_size = _get_map_size_;
  map_channel->extra_ops->get_trace_bits = _get_trace_bits_;

  return map_channel;

}

void afl_map_channel_deinit(map_based_channel_t *map_channel) {

  ck_free(map_channel->super.operations);
  ck_free(map_channel->extra_ops);
  afl_sharedmem_deinit(map_channel->shared_map);

  ck_free(map_channel);

}

u8 *_get_trace_bits_(map_based_channel_t *obs_channel) {

  return obs_channel->shared_map->map;

}

size_t _get_map_size_(map_based_channel_t *obs_channel) {

  return obs_channel->shared_map->map_size;

}

