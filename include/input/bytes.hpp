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

#ifndef LIBAFL_INPUT_BYTES_H
#define LIBAFL_INPUT_BYTES_H

#include "result.hpp"
#include "input/input.hpp"

namespace afl {

class BytesInput : public Input {

  u8* bytes;
  size_t bytesCount;

public:

  BytesInput(u8* buffer, size_t size) bytes(buffer), bytesCount(size) {}
  BytesInput(): BytesInput(nullptr, 0) {}

  /*
    Serialize the input to a buffer.
  */
  Result<size_t> Serialize(u8* buffer, size_t size) override;
  
  /*
    Deserialize the input from a buffer.
  */
  Result<size_t> Deserialize(u8* buffer, size_t size) override;
  
  /*
    Copy this instance.
  */
  Result<Input*> Copy() override;

  /*
    Assign an instance. Maybe return an error on type mistmatch? But requires dyncast.
  */
  void Assign(Input*) override;
  
  /*
    Clear the input content.
  */
  void Clear() override;

};

} // namespace afl

#endif

