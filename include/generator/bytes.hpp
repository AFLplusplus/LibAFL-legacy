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

#include "generator/generator.hpp"
#include "input/bytes.hpp"

const size_t kBytesGeneratorDefaultMaxSize = 4096;

namespace afl {

class BytesGenerator : public Generator {
protected:
  size_t maxSize;

 public:
  BytesGenerator(RandomState* random_state, size_t max_size)
      : Generator(random_state), maxSize(max_size) {}
  BytesGenerator(RandomState* random_state)
      : BytesGenerator(random_state, kBytesGeneratorDefaultMaxSize) {}

  virtual Result<Input*> Generate() override {
    size_t size = GetRandomState()->Below(maxSize);
    std::string generated;
    generated.resize(size);

    for (size_t i = 0; i < size; ++i) {
      generated[i] = static_cast<char>(GetRandomState()->Below(256));
    }

    return new BytesInput(generated);
  }

  virtual Result<Input*> GenerateDummy() override {
    return new BytesInput(std::string(64, '\0'));
  }
  
  size_t GetMaxSize() {
    return maxSize;
  }
};

class PrintableGenerator : public BytesGenerator {
 public:
  using BytesGenerator::BytesGenerator;

  virtual Result<Input*> Generate() override {
    static const char printables[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        " \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    size_t size = GetRandomState()->Below(maxSize);
    std::string generated;
    generated.resize(size);

    for (size_t i = 0; i < size; ++i) {
      generated[i] =
          printables[GetRandomState()->Below(sizeof(printables) - 1)];
    }

    return new BytesInput(generated);
  }

  virtual Result<Input*> GenerateDummy() override {
    return new BytesInput(std::string(64, '0'));
  }
};

}  // namespace afl
