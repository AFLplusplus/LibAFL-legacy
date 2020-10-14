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

#ifndef LIBAFL_RESULT_H
#define LIBAFL_RESULT_H

#include "errors.hpp"
#include "debug.hpp"

namespace afl {

template <typename OkType>
class Result {

  enum { kOk, kError, kUnknownError } tag;

  union {

    OkType ok;
    Error *error;

  } value;

 public:
  Result() {

  }

  Result(OkType ok) {

    tag = kOk;
    value.ok = ok;

  }

  Result(Error *error) {

    tag = kError;
    value.error = error;

  }

  inline OkType Expect(const char *message) {

    if (!IsOk()) {

      if (IsUnkErr())
        FATAL("Result::Expect failed at '", message, "' with unknown error.");
      else
        FATAL("Result::Expect failed at '", message, "' with error '", value.error->Message(), "' from ",
              value.error->GetSrcFile(), ":", value.error->GetSrcLine());

    }

    return value.ok;

  }

  inline OkType Unwrap() {

    if (!IsOk()) {

      if (IsUnkErr())
        FATAL("Result::Unwrap failed with unknown error.");
      else
        FATAL("Result::Unwrap failed with error '", value.error->Message(), "' from ", value.error->GetSrcFile(), ":",
              value.error->GetSrcLine());

    }

    return value.ok;

  }

  inline operator OkType() {

    return Unwrap();

  }

  inline bool IsOk() {

    return tag == kOk;

  }

  inline bool IsErr() {

    return tag == kError;

  }

  inline bool IsUnkErr() {

    return tag == kUnknownError;

  }

  static Result Ok(OkType ok) {

    return Result(ok);

  }

  static Result Err(Error *error) {

    Result result;
    result.tag = kError;
    result.value.error = error;
    return result;

  }

  static Result UnkErr() {

    Result result;
    result.tag = kUnknownError;
    return result;

  }

};

}  // namespace afl

#endif

