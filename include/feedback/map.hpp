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

#include "types.hpp"
#include "feedback/feedback.hpp"
#include "feedback/reducers.hpp"
#include "feedback/mapmeta.hpp"
#include "observation_channel/map.hpp"
#include "observation_channel/hitcounts.hpp"

#include <algorithm>  // std::fill_n

namespace afl {

/*
  Base template type for MapFeedback, it is not limited to arrays so that can be used
  with classes such as std::bitset
*/
template<typename MapType, typename MapBaseType, size_t map_size, typename ObvervationChannelType, auto ReduceFunction, MapBaseType init_value = 0, typename EntryMetaType = void>
class BaseMapFeedback : public Feedback {

  MapType virginMap;

public:

  MapType& GetVirginMap() {
    return virginMap;
  }

  float IsInteresting(Executor* executor) override;

};

/*
  Track new findings using a MapEntryMetadata.
*/
template<typename MapType, typename MapBaseType, size_t map_size, typename ObvervationChannelType, auto ReduceFunction, MapBaseType init_value, typename EntryMetaType>
float BaseMapFeedback<MapType, MapBaseType, map_size, ObvervationChannelType, ReduceFunction, init_value, EntryMetaType>::IsInteresting(Executor* executor) {
  
  bool found_new = false, found_increment = false;

  auto meta = new EntryMetaType();

  for (auto ob : executor->GetObservationChannels()) {
    if (auto hmob = dynamic_cast<ObvervationChannelType*>(ob)) {
    
      size_t size = hmob->GetSize();
      if (map_size < size) continue; // maybe we should abort instead?
    
      auto trace_map = hmob->GetMap();
    
      for (size_t i = 0; i < size; ++i) {
  
        MapBaseType old_entry = virginMap[i];
        MapBaseType trace_entry = static_cast<MapBaseType>(trace_map[i]);
        MapBaseType new_entry = ReduceFunction(old_entry, trace_entry);

        if (new_entry != old_entry) {

          if (old_entry == init_value) {
            found_new = true;
            meta->AddNewMapEntry(i);
          } else {
            found_increment = true;
            meta->AddIncrementMapEntry(i);
          }
          virginMap[i] = new_entry;

        }

      }
    
    }
  }
  
  if (GetOwnCorpus()) {

    if (found_new || found_increment) {

      auto entry = new Entry(executor->GetCurrentInput());
      entry->AddMeta(meta);
      GetOwnCorpus()->Insert(entry).expect("Cannot add entry to corpus");
      
    }
    
    // never add to the Engine corpus when there is a Feedback specific corpus
    return 0.0;

  }

  if (found_new) return 1.0;
  if (found_increment) return 0.5;
  return 0.0;

}

/*
  This is an unoptimized version without EntryMetaType. For the common cases, with u8 as MapBaseType, see the next specialization.
*/
template<typename MapType, typename MapBaseType, size_t map_size, typename ObvervationChannelType, auto ReduceFunction, MapBaseType init_value>
class BaseMapFeedback<MapType, MapBaseType, map_size, ObvervationChannelType, ReduceFunction, init_value, void> : public Feedback {

  MapType virginMap;

public:

  MapType& GetVirginMap() {
    return virginMap;
  }

  float IsInteresting(Executor* executor) override;

};

template<typename MapType, typename MapBaseType, size_t map_size, typename ObvervationChannelType, auto ReduceFunction, MapBaseType init_value>
float BaseMapFeedback<MapType, MapBaseType, map_size, ObvervationChannelType, ReduceFunction, init_value, void>::IsInteresting(Executor* executor) {
  
  bool found_new = false, found_increment = false;

  for (auto ob : executor->GetObservationChannels()) {
    if (auto hmob = dynamic_cast<ObvervationChannelType*>(ob)) {
    
      size_t size = hmob->GetSize();
      if (map_size < size) continue; // maybe we should abort instead?
    
      auto trace_map = hmob->GetMap();
    
      for (size_t i = 0; i < size; ++i) {
  
        MapBaseType old_entry = virginMap[i];
        MapBaseType trace_entry = static_cast<MapBaseType>(trace_map[i]);
        MapBaseType new_entry = ReduceFunction(old_entry, trace_entry);

        if (new_entry != old_entry) {

          if (old_entry == init_value)
            found_new = true;
          else
            found_increment = true;
          virginMap[i] = new_entry;

        }

      }
    
    }
  }
  
  if (GetOwnCorpus()) {

    if (found_new || found_increment) {

      auto entry = new Entry(executor->GetCurrentInput());
      GetOwnCorpus()->Insert(entry).expect("Cannot add entry to corpus");
      
    }
    
    // never add to the Engine corpus when there is a Feedback specific corpus
    return 0.0;

  }

  if (found_new) return 1.0;
  if (found_increment) return 0.5;
  return 0.0;

}

/*
  Template specialization for classic AFL hitcounts.
*/
template<size_t map_size>
class BaseMapFeedback<u8[map_size], u8, map_size, HitcountsMapObservationChannel, ReducerMax<u8>, 0, void> : public Feedback {

  u8 virginMap[map_size];

public:

  auto& GetVirginMap() {
    return virginMap;
  }

  float IsInteresting(Executor* executor) override;

};

template<size_t map_size>
float BaseMapFeedback<u8[map_size], u8, map_size, HitcountsMapObservationChannel, ReducerMax<u8>, 0, void>::IsInteresting(Executor* executor) {
  
  float ret = 0.0;
  
  for (auto ob : executor->GetObservationChannels()) {
    if (auto hmob = dynamic_cast<HitcountsMapObservationChannel*>(ob)) {
    
      size_t size = hmob->GetSize();
      if (map_size < size) continue; // maybe we should abort instead?
    
      auto trace_map = hmob->GetMap();

#ifdef WORD_SIZE_64

      u64 *current = reinterpret_cast<u64*>(trace_map);
      u64 *virgin = reinterpret_cast<u64*>(virginMap);

      size_t i = (map_size >> 3);

#else

      u32 *current = reinterpret_cast<u32*>(trace_map);
      u32 *virgin = reinterpret_cast<u32*>(virginMap);

      size_t i = (map_size >> 2);

#endif

      while (i--) {

        /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
           that have not been already cleared from the virgin map - since this will
           almost always be the case. */

        // the (*current) is unnecessary but speeds up the overall comparison
        if (unlikely(*current) && unlikely(*current & *virgin)) {

          if (likely(ret < 2)) {

            u8 *cur = reinterpret_cast<u8*>(current);
            u8 *vir = reinterpret_cast<u8*>(virgin);

            /* Looks like we have not found any new bytes yet; see if any non-zero
               bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

            if (*virgin == 0xffffffffffffffff || (cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) || (cur[4] && vir[4] == 0xff) ||
                (cur[5] && vir[5] == 0xff) || (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) {

              ret = 1.0;

            } else {

              ret = 0.5;

            }

#else

            if (*virgin == 0xffffffff || (cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff))
              ret = 1.0;
            else
              ret = 0.5;

#endif                                                                                             /* ^WORD_SIZE_64 */

          }

          *virgin &= ~*current;

        }

        ++current;
        ++virgin;

      }
      
      break;
    
    }
  }

  if (GetOwnCorpus()) {

    if (ret > 0.0) {

      auto entry = new Entry(executor->GetCurrentInput());
      GetOwnCorpus()->Insert(entry).expect("Cannot add entry to corpus");
      
    }
    
    // never add to the Engine corpus when there is a Feedback specific corpus
    return 0.0;

  }

  return ret;

}

/*
  MapFeedback use an MapBaseType array.
*/
template<typename MapBaseType, size_t map_size, typename ObvervationChannelType, auto ReduceFunction, MapBaseType init_value = 0, typename EntryMetaType = void>
class MapFeedback : public BaseMapFeedback<MapBaseType[map_size], MapBaseType, map_size, ObvervationChannelType, ReduceFunction, init_value, EntryMetaType> {

public:

  MapFeedback() {
    std::fill_n(this->GetVirginMap(), map_size, init_value);
  }

};

// TODO(andrea) maybe add an EntryMetadata with the has of the map.

/*
  Define common MapFeedback types.
*/
template<typename MapBaseType, size_t map_size, typename ObvervationChannelType>
using MaxMapFeedback = MapFeedback<MapBaseType, map_size, ObvervationChannelType, ReducerMax<MapBaseType>>;

template<typename MapBaseType, size_t map_size, typename ObvervationChannelType>
using MinMapFeedback = MapFeedback<MapBaseType, map_size, ObvervationChannelType, ReducerMin<MapBaseType>, MapBaseType(-1)>;

template<size_t map_size>
using MaxMapFeedbackU8 = MapFeedback<u8, map_size, MapObservationChannel<u8>, ReducerMax<u8>>;

template<size_t map_size>
using MinMapFeedbackU8 = MapFeedback<u8, map_size, MapObservationChannel<u8, u8(-1)>, ReducerMin<u8>, u8(-1)>;

template<size_t map_size>
using MaxMapFeedbackU16 = MapFeedback<u16, map_size, MapObservationChannel<u16>, ReducerMax<u16>>;

template<size_t map_size>
using MinMapFeedbackU16 = MapFeedback<u16, map_size, MapObservationChannel<u16, u16(-1)>, ReducerMin<u16>, u16(-1)>;

template<size_t map_size>
using MaxMapFeedbackU32 = MapFeedback<u32, map_size, MapObservationChannel<u32>, ReducerMax<u32>>;

template<size_t map_size>
using MinMapFeedbackU32 = MapFeedback<u32, map_size, MapObservationChannel<u32, u32(-1)>, ReducerMin<u32>, u32(-1)>;

template<size_t map_size>
using MaxMapFeedbackU64 = MapFeedback<u64, map_size, MapObservationChannel<u64>, ReducerMax<u64>>;

template<size_t map_size>
using MinMapFeedbackU64 = MapFeedback<u64, map_size, MapObservationChannel<u64, u64(-1)>, ReducerMin<u64>, u64(-1)>;

template<size_t map_size>
using HitcountsMapFeedback = MapFeedback<u8, map_size, HitcountsMapObservationChannel, ReducerMax<u8>>;

} // namespace afl

#endif
