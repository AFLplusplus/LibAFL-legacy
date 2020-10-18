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
#include <typeindex>
#include <vector>
#include <chrono>

namespace afl {

class Stage;
class Entry;

class Engine {

protected:

  RandomState* randomState;

  std::vector<Feedback*> feedbacks;
  std::vector<Stage*> stages;

  Corpus* mainCorpus;
  Executor* executor;

  size_t executions;
  std::chrono::milliseconds startTime;
  std::chrono::milliseconds lastFindingTime;
  
  std::unordered_map<std::type_index, Monitor*> monitors;

public:

  Engine(RandomState* random_state, Executor* executor_, Corpus* corpus) : randomState(random_state), executor(executor_), mainCorpus(corpus) {}

  RandomState* GetRandomState() {
    return randomState;
  }
  
  void SetRandomState(RandomState* random_state) {
    randomState = random_state;
  }


  void AddFeedback(Feedback* feedback) {
    feedbacks.push_back(feedback);
  }
  
  template <class FeedbackType, typename...ArgsTypes>
  FeedbackType* CreateFeedback(ArgsTypes... args) {

    FeedbackType* obj = new FeedbackType(args...);
    AddFeedback(obj);
    return obj;

  }
  
  void AddStage(Stage* stage) {
    stages.push_back(stage);
  }
  
  template <class StageType, typename...ArgsTypes>
  StageType* CreateStage(ArgsTypes... args) {

    StageType* obj = new StageType(GetRandomState(), this, args...);
    AddStage(obj);
    return obj;

  }

  Corpus* GetMainCorpus() {
    return mainCorpus;
  }
  
  Executor* GetExecutor() {
    return executor;
  }

  size_t GetExecutions() {
    return executions;
  }

  bool AddMonitor(Monitor* monitor) {
    auto index = std::type_index(typeid(*monitor));
    auto it = monitors.find(index);
    if (it != monitors.end())
      return false;
    monitors[index] = monitor;
    return true;
  }
  
  Monitor* GetMonitor(const std::type_index index) {
    auto it = monitors.find(index);
    if (it == monitors.end())
      return nullptr;
    return it->second;
  }
  
  Monitor* GetMonitor(const std::type_info& info) {
    return GetMonitor(std::type_index(info));
  }
  
  template<typename MonitorType>
  MonitorType* GetMonitor() {
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

