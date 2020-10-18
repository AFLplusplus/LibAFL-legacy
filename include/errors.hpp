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

#ifndef LIBAFL_ERRORS_H
#define LIBAFL_ERRORS_H

#include "types.hpp"

#include <cerrno>
#include <cstring>

namespace afl {

class Error {
  const char* srcFile;
  size_t srcLine;

 public:
  Error(const char* src_file, size_t src_line)
      : srcFile(src_file), srcLine(src_line) {}

  virtual const char* Message() = 0;

  const char* GetSrcFile() { return srcFile; }

  size_t GetSrcLine() { return srcLine; }
};

class RuntimeError : public Error {
  const char* message;

 public:
  RuntimeError(const char* src_file, size_t src_line, const char* msg)
      : Error(src_file, src_line), message(msg) {}

  const char* Message() override { return message; }
};

class AllocationError : public Error {
 public:
  AllocationError(const char* src_file, size_t src_line)
      : Error(src_file, src_line) {}

  const char* Message() override { return "Cannot allocate memory"; }
};

class OSError : public Error {
  int errNum;

 public:
  OSError(const char* src_file, size_t src_line, int err_num)
      : Error(src_file, src_line), errNum(err_num) {}

  const char* Message() override { return strerror(errNum); }
};

class OutOfBoundsError : public Error {
 public:
  OutOfBoundsError(const char* src_file, size_t src_line)
      : Error(src_file, src_line) {}

  const char* Message() override { return "Out of bound access"; }
};

class NotEnoughSpaceError : public Error {
 public:
  NotEnoughSpaceError(const char* src_file, size_t src_line)
      : Error(src_file, src_line) {}

  const char* Message() override { return "Not enough space in container"; }
};

class EmptyContainerError : public Error {
 public:
  EmptyContainerError(const char* src_file, size_t src_line)
      : Error(src_file, src_line) {}

  const char* Message() override { return "Empty container"; }
};

}  // namespace afl

#endif
