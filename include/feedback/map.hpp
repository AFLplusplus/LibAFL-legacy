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

#ifndef LIBAFL_FEEDBACK_MAP_H
#define LIBAFL_FEEDBACK_MAP_H

#include "feedback/feedback.h"
#include "feedback/reducers.h"

#include <algorithm>  // std::fill_n

namespace afl {

/*
  Base template type for MapFeedback, it is not limited to arrays so that can be used
  with classes such as std::bitset
*/
template<typename MapType, typename MapBaseType, size_t map_size, typename ObvervationChannelType, typename ReduceFunction, MapBaseType init_value = 0>
class BaseMapFeedback : public Feedback {

  MapType virginMap;

public:

  MapType& GetVirginMap() {
    return virginMap;
  }

  float IsInteresting(Executor* executor) override;

};

/*
  MapFeedback use an MapBaseType array.
*/
template<typename MapBaseType, size_t map_size, typename ObvervationChannelType, typename ReduceFunction, MapBaseType init_value = 0>
class MapFeedback : public BaseMapFeedback<MapBaseType[map_size], map_size, ObvervationChannelType, ReduceFunction, init_value> {

public:

  MapFeedback() {
    std::fill_n(GetVirginMap(), map_size, init_value);
  }

};

/*
  Define common MapFeedback type with default behaviours
*/
template<typename MapBaseType, size_t map_size, typename ObvervationChannelType>
using MaxMapFeedback<MapBaseType> = MapFeedback<MapBaseType, map_size, ObvervationChannelType, ReducerMax<MapBaseType>>

template<typename MapBaseType, size_t map_size, typename ObvervationChannelType>
using MinMapFeedback<MapBaseType> = MapFeedback<MapBaseType, map_size, ObvervationChannelType, ReducerMin, (u64)(-1)>

/*
  TODO this is an unoptimized version. For the common cases, use template specialization and
  define some IsInteresting function using the AFL has_new_bits magic.
*/
template<typename MapType, typename MapBaseType, size_t map_size, typename ObvervationChannelType, typename ReduceFunction, MapBaseType init_value = 0>
float BaseMapFeedback<MapType, map_size, ReduceFunction>::IsInteresting(Executor* executor) {
  
  bool found_new = false, found_increment = false;

  for (auto ob : executor->GetObservationChannels()) {
    if (auto hmob = dynamic_cast<ObvervationChannelType*>(ob)) {
    
      if (map_size != hmob->GetSize()) continue;
    
      auto trace_map = hmob->GetTraceMap();
    
      for (size_t i = 0; i < map_size; ++i) {
  
        MapBaseType old_entry = virginMap[i];
        MapBaseType trace_entry = static_cast<MapBaseType>(trace_map[i]);
        MapBaseType new_entry = ReduceFunction(old_entry, trace_entry);

        if (new_entry != old_entry) {

          if (old_entry == init_value)
            found_new = true;
          else
            found_increment = true;
          virginMap[i] = e;

        }

      }
    
    }
  }
  
  if (ownCorpus) {
    if (found_new || found_increment)
      feedback_queue->add(create<QueueEntry>(executor->getCurrentInput(), feedback_queue));
    
    // never add to the Engine corpus when there is a Feedback specific corpus
    return 0.0;
  }

  if (found_new) return 1.0;
  if (found_increment) return 0.5;
  return 0.0;

}

} // namespace afl

#endif
