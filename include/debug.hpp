/*
   american fuzzy lop++ - debug / error handling macros
   ----------------------------------------------------

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

 */

/* This file contains helpers for debugging and fancy Printing */

#pragma once

#include <iostream>

/*******************
 * Terminal colors *
 *******************/

#ifdef USE_COLOR

#define cBLK "\x1b[0;30m"
#define cRED "\x1b[0;31m"
#define cGRN "\x1b[0;32m"
#define cBRN "\x1b[0;33m"
#define cBLU "\x1b[0;34m"
#define cMGN "\x1b[0;35m"
#define cCYA "\x1b[0;36m"
#define cLGR "\x1b[0;37m"
#define cGRA "\x1b[1;90m"
#define cLRD "\x1b[1;91m"
#define cLGN "\x1b[1;92m"
#define cYEL "\x1b[1;93m"
#define cLBL "\x1b[1;94m"
#define cPIN "\x1b[1;95m"
#define cLCY "\x1b[1;96m"
#define cBRI "\x1b[1;97m"
#define cRST "\x1b[0m"

#define bgBLK "\x1b[40m"
#define bgRED "\x1b[41m"
#define bgGRN "\x1b[42m"
#define bgBRN "\x1b[43m"
#define bgBLU "\x1b[44m"
#define bgMGN "\x1b[45m"
#define bgCYA "\x1b[46m"
#define bgLGR "\x1b[47m"
#define bgGRA "\x1b[100m"
#define bgLRD "\x1b[101m"
#define bgLGN "\x1b[102m"
#define bgYEL "\x1b[103m"
#define bgLBL "\x1b[104m"
#define bgPIN "\x1b[105m"
#define bgLCY "\x1b[106m"
#define bgBRI "\x1b[107m"

#else

#define cBLK ""
#define cRED ""
#define cGRN ""
#define cBRN ""
#define cBLU ""
#define cMGN ""
#define cCYA ""
#define cLGR ""
#define cGRA ""
#define cLRD ""
#define cLGN ""
#define cYEL ""
#define cLBL ""
#define cPIN ""
#define cLCY ""
#define cBRI ""
#define cRST ""

#define bgBLK ""
#define bgRED ""
#define bgGRN ""
#define bgBRN ""
#define bgBLU ""
#define bgMGN ""
#define bgCYA ""
#define bgLGR ""
#define bgGRA ""
#define bgLRD ""
#define bgLGN ""
#define bgYEL ""
#define bgLBL ""
#define bgPIN ""
#define bgLCY ""
#define bgBRI ""

#endif

/*************************
 * Box drawing sequences *
 *************************/

#ifdef FANCY_BOXES

#define SET_G1 "\x1b)0"   /* Set G1 for box drawing    */
#define RESET_G1 "\x1b)B" /* Reset G1 to ASCII         */
#define bSTART "\x0e"     /* Enter G1 drawing mode     */
#define bSTOP "\x0f"      /* Leave G1 drawing mode     */
#define bH "q"            /* Horizontal line           */
#define bV "x"            /* Vertical line             */
#define bLT "l"           /* Left top corner           */
#define bRT "k"           /* Right top corner          */
#define bLB "m"           /* Left bottom corner        */
#define bRB "j"           /* Right bottom corner       */
#define bX "n"            /* Cross                     */
#define bVR "t"           /* Vertical, branch right    */
#define bVL "u"           /* Vertical, branch left     */
#define bHT "v"           /* Horizontal, branch top    */
#define bHB "w"           /* Horizontal, branch bottom */

#else

#define SET_G1 ""
#define RESET_G1 ""
#define bSTART ""
#define bSTOP ""
#define bH "-"
#define bV "|"
#define bLT "+"
#define bRT "+"
#define bLB "+"
#define bRB "+"
#define bX "+"
#define bVR "+"
#define bVL "+"
#define bHT "+"
#define bHB "+"

#endif

#define TERM_HOME "\x1b[H"
#define TERM_CLEAR TERM_HOME "\x1b[2J"
#define cEOL "\x1b[0K"
#define CURSOR_HIDE "\x1b[?25l"
#define CURSOR_SHOW "\x1b[?25h"

#define _TOSTRING1(x) #x
#define _TOSTRING(x) _TOSTRING1(x)

#ifdef DEBUG_BUILD
#define DEBUG(...)                                                          \
  PrintErr(cMGN "[D]" cGRA " [" __FILE__ ":" _TOSTRING(__LINE__) "] " cRST, \
           __VA_ARGS__, cRST "\n")
#else
#define DEBUG(...) \
  do {             \
  } while (0)
#endif

/* Die with a verbose non-OS fatal error message. */

#define FATAL(...)                                                             \
  do {                                                                         \
    PrintErr(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD "\n[-] FATAL ERROR : " cRST, \
             __VA_ARGS__, cLRD "\n       Location : " cRST, __func__,          \
             "(), " __FILE__ ":", __LINE__, "\n\n");                           \
    std::exit(1);                                                              \
                                                                               \
  } while (0)

/* Die by calling afl_abort() to provide a core dump. */

#define ABORT(...)                                                      \
  do {                                                                  \
    PrintErr(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD                       \
             "\n[-] PROGRAM ABORT : " cRST,                             \
             __VA_ARGS__, cLRD "\n         Location : " cRST, __func__, \
             "(), " __FILE__ ":", __LINE__, "\n\n");                    \
    std::abort();                                                       \
                                                                        \
  } while (0)

/* Die while also including the output of perror(). */

/*#define PFATAL(...) \
  do { \
                                                                                                \
    afl_Print_error_fmt(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD "\n[-]  SYSTEM
  ERROR : " cRST __VA_ARGS__);       \
    afl_Print_error_fmt(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n",
  __FUNCTION__, __FILE__, __LINE__); \
    afl_Print_error_fmt(cLRD "       OS message : " cRST "%s\n",
  strerror(errno));                             \
    afl_Print_error_flush();  \
    afl_exit(1); \
                                                                                                \
  } while (0)*/

#ifndef CHECK
#define CHECK(expr)                \
  if (!likely(expr)) {             \
    FATAL("CHECK failed: " #expr); \
  }
#endif

#ifdef DEBUG_BUILD
#define DCHECK(expr)                \
  if (!likely(expr)) {              \
    FATAL("DCHECK failed: " #expr); \
  }
#else
#define DCHECK(expr) \
  do {               \
  } while (0);
#endif

#undef _TOSTRING1
#undef _TOSTRING

namespace afl {

template <typename Last>
static inline void Print(Last last) {
  std::cout << last;
}

template <typename First, typename... Types>
static inline void Print(First first, Types... args) {
  std::cout << first;
  Print(args...);
}

template <typename Last>
static inline void PrintErr(Last last) {
  std::cerr << last;
}

template <typename First, typename... Types>
static inline void PrintErr(First first, Types... args) {
  std::cerr << first;
  PrintErr(args...);
}

/* Show a prefixed warning. */

template <typename... Types>
static inline void PrintWarn(Types... args) {
  PrintErr(cYEL "[!] " cBRI "WARNING: ", args..., cRST "\n");
}

/* Show a prefixed "doing something" message. */

template <typename... Types>
static inline void PrintAct(Types... args) {
  Print(cLBL "[*] " cRST, args..., cRST "\n");
}

/* Show a prefixed "success" message. */

template <typename... Types>
static inline void PrintOk(Types... args) {
  Print(cLBL "[*] " cRST, args..., cRST "\n");
}

}  // namespace afl
