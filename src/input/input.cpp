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

#include "input/input.hpp"

#include <fstream>

namespace afl {

static __thread u8 g_loadsave_file_temp_buffer[kMaxInputBytes];

Result<void> Input::LoadFromFile(const char* filename) {
  std::basic_ifstream<u8> ifile(filename, std::ios::binary);
  ifile.read(g_loadsave_file_temp_buffer, kMaxInputBytes);
  auto res = Deserialize(g_loadsave_file_temp_buffer, ifile.gcount());
  if (!res.IsOk())
    return res.GetError();
  ifile.close();
  return OK();
}

Result<void> Input::SaveToFile(const char* filename) {
  std::basic_ofstream<u8> ofile(filename, std::ios::binary);
  auto size = Serialize(g_loadsave_file_temp_buffer, kMaxInputBytes);
  if (!size.IsOk())
    return size.GetError();
  ofile.write(g_loadsave_file_temp_buffer, size.Unwrap());
  ofile.close();
  return OK();
}

}  // namespace afl
