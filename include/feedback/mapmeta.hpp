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

#ifndef LIBAFL_FEEDBACK_MAPMETA_H
#define LIBAFL_FEEDBACK_MAPMETA_H

#include "debug.hpp"

#include <vector>

namespace afl {

class Feedback;

template <class Derived>
class T_MapEntryMetadata : public EntryMetadata {
  std::vector<size_t> mapEntries;
  Feedback* feedback;

 public:
  T_MapEntryMetadata(Feedback* feedback_) : feedback(feedback_) {}

  Feedback* GetFeedback() { return feedback; }

  size_t GetMapEntriesCount() { return mapEntries.size(); }

  void AddMapEntry(size_t entry) { mapEntries.push_back(entry); }

  void AddNewMapEntry(size_t entry) {
    static_cast<Derived*>(this)->AddNewMapEntry(entry);
  }

  void AddIncrementMapEntry(size_t entry) {
    static_cast<Derived*>(this)->AddIncrementMapEntry(entry);
  }

  size_t GetMapEntry(size_t index) {
    DCHECK(index < GetNewMapEntriesCount());
    return mapEntries[index];
  }
};

class MapNewsEntryMetadata : public T_MapEntryMetadata<MapNewsEntryMetadata> {
 public:
  using T_MapEntryMetadata<MapNewsEntryMetadata>::T_MapEntryMetadata;

  void AddNewMapEntry(size_t entry) { AddMapEntry(entry); }

  void AddIncrementMapEntry(size_t entry) { (void)entry; }
};

class MapIncrementsEntryMetadata
    : public T_MapEntryMetadata<MapIncrementsEntryMetadata> {
 public:
  using T_MapEntryMetadata<MapIncrementsEntryMetadata>::T_MapEntryMetadata;

  void AddNewMapEntry(size_t entry) { AddMapEntry(entry); }

  void AddIncrementMapEntry(size_t entry) { AddMapEntry(entry); }
};

}  // namespace afl

#endif
