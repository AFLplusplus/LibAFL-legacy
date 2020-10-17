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

#ifndef LIBAFL_INPUT_INPUT_H
#define LIBAFL_INPUT_INPUT_H

#include "result.hpp"
#include "types.hpp"

namespace afl {

/*
  An Input entity defines one possible sample from the Input Space and can hold properties about the input itself, the
  relation between the input and the SUT, or the input and the specification.
*/
class Input {
  
public:

  /*
    Serialize the input to a buffer.
  */
  virtual Result<size_t> Serialize(u8* buffer, size_t size) = 0;
  
  /*
    Deserialize the input from a buffer.
  */
  virtual Result<size_t> Deserialize(u8* buffer, size_t size) = 0;
  
  /*
    Copy this instance.
  */
  virtual Result<Input*> Copy() = 0;

  /*
    Assign an instance. Maybe return an error on type mistmatch? But requires dyncast.
  */
  virtual void Assign(Input* input) = 0;
  
  /*
    Clear the input content.
  */
  virtual void Clear() = 0;

  /*
    Serialization to files functions.
  */
  void SaveToFile(char* filename);
  void LoadFromFile(char* filename);

};

} // namespace afl

#endif

