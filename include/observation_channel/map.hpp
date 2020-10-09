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

#ifndef LIBAFL_OBSERVATION_CHANNEL_MAP_H
#define LIBAFL_OBSERVATION_CHANNEL_MAP_H

#include "observation_channel/observation_channel.h"

namespace afl {

template<typename EntryType>
class MapObservationChannel {

protected:

  EntryType* traceMap;
  size_t traceMapSize;

public:

  MapObservationChannel(EntryType* trace_map, size_t trace_map_size) : traceMap(trace_map), traceMapSize(trace_map_size) {}

  /*
    Reset the channel.
  */
  virtual void Reset() override {
    memset(traceMap, 0, traceMapSize * sizeof(traceMap));
  }
  
  /*
    Getters.
  */
  EntryType* GetMap() {
    return traceMap;
  }
  size_t GetSize() {
    return traceMapSize;
  }
  
};

} // namespace afl

#endif

