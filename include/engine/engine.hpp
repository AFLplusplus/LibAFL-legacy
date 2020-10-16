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

#ifndef LIBAFL_ENGINE_ENGINE_H
#define LIBAFL_ENGINE_ENGINE_H

#include "result.hpp"
#include "input/input.hpp"
#include "engine/monitor.hpp"

#include <unordered_map>
#include <typeinfo>
#include <vector>
#include <chrono>

namespace afl {

class Stage;
class Entry;

class Engine {

  std::vector<Stage*> stages;
  std::vector<Feedback*> feedbacks;

  Corpus* mainCorpus;
  Executor* executor;

  size_t executions;
  std::chrono::milliseconds startTime;
  
  std::unordered_map<std::type_index, Monitor*> monitors;

public:

  inline bool AddMonitor(Monitor* monitor) {
    auto index = std::type_index(typeid(*monitor));
    auto it = monitors.find(index);
    if (it != monitors.end())
      return false;
    monitors[index] = monitor;
    return true;
  }
  
  inline Monitor* GetMonitor(const std::type_index index) {
    auto it = monitors.find(index);
    if (it == monitors.end())
      return nullptr;
    return it->second;
  }
  
  inline Monitor* GetMonitor(const std::type_info& info) {
    return GetMonitor(std::type_index(info));
  }
  
  template<typename MonitorType>
  inline MonitorType* GetMonitor() {
    return GetMonitor(typeid(MonitorType));
  }

  /* Useful hooks */
  virtual void PreExec() {}
  virtual void PostExec() {}

  /*
    Execute an input, entry is the entry used to generate this input (optional)
  */
  /* virtual */ bool Execute(Input* input, Entry* entry);
  
  bool Execute(Input* input) {
    return Execute(input, nullptr);
  }

  void Run();

};

} // namespace afl

#endif

