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

#include "debug.hpp"
#include "errors.hpp"
#include "types.hpp"

namespace afl {

#define OK Result<void>::Ok

#define ERR(type, ...) (new (type)(__FILE__, __LINE__, ##__VA_ARGS__))

#define TRY(result)                 \
  ({                                \
    auto _res = (result);           \
    if (unlikely(_res.IsErr()))     \
      return _res.UnsafeGetError(); \
    _res.UnsafeUnwrap();            \
  })

#define TRY_HANDLE(result, block)   \
  ({                                \
    auto _res = (result);           \
    if (unlikely(_res.IsErr())) {   \
      block;                        \
      return _res.UnsafeGetError(); \
    }                               \
    _res.UnsafeUnwrap();            \
  })

#define NEW(type, ...)                      \
  ({                                        \
    try {                                   \
      Result<type*>(new type(__VA_ARGS__)); \
    } catch (std::bad_alloc & ba) {         \
      Result<type*>(ERR(AllocationError));  \
    }                                       \
  })

template <typename OkType>
class Result {
  enum { kOk, kError } tag;

  union {
    OkType ok;
    Error* error;

  } value;

 public:
  Result(OkType ok) {
    tag = kOk;
    value.ok = ok;
  }

  Result(Error* error) {
    tag = kError;
    value.error = error;
  }

  Error* GetError() {
    if (IsErr())
      return value.error;
    return nullptr;
  }

  OkType Expect(const char* message) {
    if (IsErr()) {
      ABORT("Result::Expect failed at '", message, "' with ", typeid(*value.error).name(), " '", value.error->Message(), "' from ", value.error->GetSrcFile(), ":", value.error->GetSrcLine());
    }

    return value.ok;
  }

  OkType Unwrap() {
    if (IsErr()) {
      ABORT("Result::Unwrap failed with ", typeid(*value.error).name(), " '",
            value.error->Message(), "' from ", value.error->GetSrcFile(), ":",
            value.error->GetSrcLine());
    }

    return value.ok;
  }

  Error* UnsafeGetError() { return value.error; }

  OkType UnsafeUnwrap() { return value.ok; }

  // Automatic Unwrap, can be dangerous
  /* operator OkType() {

    return Unwrap();

  } */

  bool IsOk() { return tag == kOk; }

  bool IsErr() { return tag == kError; }

  static Result<OkType> Ok(OkType ok) { return Result<OkType>(ok); }

  static Result<OkType> Err(Error* error) { return Result<OkType>(error); }
};

template <>
class Result<void> {
  Error* error;

 public:
  Result() : error(nullptr) {}

  Result(Error* error_) : error(error_) {}

  Error* GetError() { return error; }

  void Expect(const char* message) {
    if (IsErr()) {
      ABORT("Result::Expect failed at '", message, "' with ",
            typeid(*error).name(), " '", error->Message(), "' from ",
            error->GetSrcFile(), ":", error->GetSrcLine());
    }
  }

  void Unwrap() {
    if (IsErr()) {
      ABORT("Result::Unwrap failed with ", typeid(*error).name(), " '",
            error->Message(), "' from ", error->GetSrcFile(), ":",
            error->GetSrcLine());
    }
  }

  Error* UnsafeGetError() { return error; }

  void UnsafeUnwrap() {}

  bool IsOk() { return error == nullptr; }

  bool IsErr() { return error != nullptr; }

  static Result<void> Ok() { return Result<void>(); }

  static Result<void> Err(Error* error) { return Result<void>(error); }
};

}  // namespace afl

#endif
