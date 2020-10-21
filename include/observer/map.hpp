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

#pragma once

#include "observer/observation_channel.hpp"

#include <algorithm>  // std::fill_n

namespace afl {

template <typename MapType>
class BaseMapObservationChannel : public ObservationChannel {
 protected:
  MapType traceMap;
  size_t traceMapSize;

 public:
  BaseMapObservationChannel(MapType trace_map, size_t trace_map_size)
      : traceMap(trace_map), traceMapSize(trace_map_size) {}

  /*
    Getters.
  */
  MapType GetMap() { return traceMap; }
  virtual size_t GetSize() { return traceMapSize; }
};

template <typename MapBaseType, MapBaseType init_value = 0>
class MapObservationChannel : public BaseMapObservationChannel<MapBaseType*> {
 public:
  using BaseMapObservationChannel<MapBaseType*>::BaseMapObservationChannel;

  /*
    Reset the channel.
  */
  Result<void> Reset() override {
    std::fill_n(this->GetMap(), init_value, this->GetSize());
    MEM_BARRIER();
    return OK();
  }
};

}  // namespace afl
