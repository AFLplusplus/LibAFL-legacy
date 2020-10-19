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

#include "corpus/corpus.hpp"
#include "executor/executor.hpp"
#include "feedback/feedback.hpp"
#include "stage/stage.hpp"

using namespace afl;

Result<bool> Engine::Execute(Input* input, Entry* entry) {
  if (startTime == std::chrono::milliseconds{0})
    startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());

  TRY(executor->ResetObservationChannels());
  TRY(executor->PlaceInput(input));

  TRY(PreExec());

  // TODO execution time

  TRY(executor->RunTarget());
  ++executions;

  TRY(PostExec());

  TRY(executor->PostExecObservationChannels());

  // The first IsInteresting that wants to add an input to the mainCorpus,
  // if any, is responsible to initialize new_entry.
  Entry* new_entry = nullptr;
  float rate = 0.0;

  for (auto feedback : feedbacks) {
    rate += TRY_HANDLE(feedback->IsInteresting(executor, new_entry), {
      if (new_entry)
        delete new_entry;
    });
  }

  if (rate >= 0.5) {
    mainCorpus->Insert(new_entry);
    return true;
  } else if (new_entry) {
    delete new_entry;
  }

  return false;
}

Result<void> Engine::FuzzOne() {
  Entry* entry = TRY(mainCorpus->Get());
  Input* input = TRY(TRY(entry->LoadInput())->Copy());

  for (auto stage : stages) {
    currentStage = stage;
    TRY_HANDLE(stage->Perform(input, entry), { delete input; });
  }

  delete input;
  return OK();
}
