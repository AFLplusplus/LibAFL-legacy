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

#include "engine/engine.hpp"
#include "feedback/feedback.hpp"
#include "executor/executor.hpp"
#include "corpus/corpus.hpp"
#include "stage/stage.hpp"

using namespace afl;

bool Engine::Execute(Input* input, Entry* entry) {

  if (startTime == std::chrono::milliseconds{0})
    startTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());

  executor->ResetObservationChannels();
  executor->PlaceInput(input);
  
  PreExec();
  
  // TODO execution time
  
  executor->RunTarget();
  ++executions;
  
  PostExec();

  executor->PostExecObservationChannels();
  
  // TODO find a way to pass metadatas for the entry
  
  float rate = 0.0;
  for(auto feedback : feedbacks)
    rate += feedback->IsInteresting(executor, input);

  if (rate >= 0.5) {
  
    auto entry = new Entry(input);
    //entry->AddMeta(meta);
    mainCorpus->Insert(entry);
    
    return true;
  
  }
  
  return false;

}

void Engine::FuzzOne() {

  Entry* entry = mainCorpus->Get();
  Input* input = entry->LoadInput()->Copy();
  
  for (auto stage : stages) {
  
    stage->Perform(input, entry);
  
  }
  
  delete input;
  
}