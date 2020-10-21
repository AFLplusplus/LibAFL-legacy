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

#include "input/input.hpp"
#include "result.hpp"

#include <string>
#include <utility>

namespace afl {

// TODO use incremental call to std::string::reserve()

class BytesInput : public Input {
  std::string bytes;

 public:
  BytesInput(u8* buffer, size_t size)
      : bytes(reinterpret_cast<char*>(buffer), size) {}
  BytesInput(const std::string& string) : bytes(string) {}
  BytesInput(std::string&& string) : bytes(string) {}
  BytesInput(const BytesInput& bytes_input) : bytes(bytes_input.bytes) {}
  BytesInput(BytesInput&& bytes_input) : bytes(std::move(bytes_input.bytes)) {}
  BytesInput() {}

  std::string& Bytes() { return bytes; }

  /*
    Serialize the input to a buffer.
  */
  Result<size_t> Serialize(u8* buffer, size_t size) override {
    if (bytes.size() > size)
      return ERR(NotEnoughSpaceError);
    std::copy_n(bytes.data(), bytes.size(), buffer);
    return bytes.size();
  }

  /*
    Deserialize the input from a buffer.
  */
  Result<size_t> Deserialize(u8* buffer, size_t size) override {
    bytes.copy(reinterpret_cast<char*>(buffer), size);
    return bytes.size();
  }

  /*
    Copy this instance.
  */
  Result<Input*> Copy() override { return new BytesInput(*this); }

  /*
    Assign an instance. Maybe return an error on type mistmatch? But requires
    dyncast.
  */
  Result<void> Assign(Input* input) override {
    DCHECK(dynamic_cast<BytesInput*>(input));  // maybe use Error for this check
    bytes = static_cast<BytesInput*>(input)->bytes;
    return OK();
  }

  /*
    Clear the input content.
  */
  void Clear() override { bytes.clear(); }
};

}  // namespace afl
