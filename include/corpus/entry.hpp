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

#ifndef LIBAFL_CORPUS_ENTRY_H
#define LIBAFL_CORPUS_ENTRY_H

#include "input/input.hpp"

#include <typeinfo>
#include <typeindex>
#include <unordered_map>

namespace afl {

class EntryMetadata {
  
};

class Entry {

  Input* input;
  
  std::unordered_map<std::type_index, EntryMetadata*> metaDatas;

  char* fileName;
  bool isOnDisk;

public:

  Entry(Input* input_) : input(input_) {}
  
  // TODO atomic flag to avoid cache eviction while using the input.
  Input* LoadInput();
  
  bool IsOnDisk() {
    return isOnDisk;
  }
  
  const char* GetFileName() {
    return fileName;
  }
  
  inline bool AddMeta(EntryMetadata* meta) {
    auto index = std::type_index(typeid(*meta));
    auto it = metaDatas.find(index);
    if (it != metaDatas.end())
      return false;
    metaDatas[index] = meta;
    return true;
  }
  
  inline EntryMetadata* GetMeta(const std::type_index index) {
    auto it = metaDatas.find(index);
    if (it == metaDatas.end())
      return nullptr;
    return it->second;
  }
  
  inline EntryMetadata* GetMeta(const std::type_info& info) {
    return GetMeta(std::type_index(info));
  }
  
  template<typename EntryMetaType>
  inline EntryMetaType* GetMeta() {
    return GetMeta(typeid(EntryMetaType));
  }
  
};

} // namespace afl

#endif

