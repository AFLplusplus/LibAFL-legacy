use ::libc;
extern "C" {
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;
    #[no_mangle]
    fn access(__name: *const libc::c_char, __type: libc::c_int)
     -> libc::c_int;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
/* This file includes return codes for libafl. */
/* Shorthand to check for RET_SUCCESS */
/* If expr != AFL_RET_SUCCESS, run block, error is in err. Return from here will return the parent func */
/* Shorthand to check for RET_SUCCESS and assign to ret */
pub type afl_ret = libc::c_uint;
pub const AFL_RET_EMPTY: afl_ret = 20;
pub const AFL_RET_ERROR_INPUT_COPY: afl_ret = 19;
pub const AFL_RET_TRIM_FAIL: afl_ret = 18;
pub const AFL_RET_NO_FUZZ_WORKERS: afl_ret = 17;
pub const AFL_RET_ERROR_INITIALIZE: afl_ret = 16;
pub const AFL_RET_QUEUE_ENDS: afl_ret = 15;
pub const AFL_RET_WRITE_TO_CRASH: afl_ret = 14;
pub const AFL_RET_NULL_QUEUE_ENTRY: afl_ret = 13;
pub const AFL_RET_ERRNO: afl_ret = 12;
pub const AFL_RET_NULL_PTR: afl_ret = 11;
pub const AFL_RET_BROKEN_TARGET: afl_ret = 10;
pub const AFL_RET_EXEC_ERROR: afl_ret = 9;
pub const AFL_RET_ARRAY_END: afl_ret = 8;
pub const AFL_RET_SHORT_WRITE: afl_ret = 7;
pub const AFL_RET_SHORT_READ: afl_ret = 6;
pub const AFL_RET_FILE_SIZE: afl_ret = 5;
pub const AFL_RET_FILE_OPEN_ERROR: afl_ret = 4;
pub const AFL_RET_ALLOC: afl_ret = 3;
pub const AFL_RET_FILE_DUPLICATE: afl_ret = 2;
pub const AFL_RET_UNKNOWN_ERROR: afl_ret = 1;
pub const AFL_RET_SUCCESS: afl_ret = 0;
pub type afl_ret_t = afl_ret;
pub type u8_0 = uint8_t;
pub type u64_0 = libc::c_ulonglong;
pub type s32 = int32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_alloc_buf {
    pub complete_size: size_t,
    pub magic: size_t,
    pub buf: [u8_0; 0],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_input {
    pub bytes: *mut u8_0,
    pub len: size_t,
    pub copy_buf: *mut u8_0,
    pub funcs: afl_input_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_input_funcs {
    pub deserialize: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                                 _: *mut u8_0, _: size_t)
                                -> ()>,
    pub serialize: Option<unsafe extern "C" fn(_: *mut afl_input_t)
                              -> *mut u8_0>,
    pub copy: Option<unsafe extern "C" fn(_: *mut afl_input_t)
                         -> *mut afl_input_t>,
    pub restore: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                             _: *mut afl_input_t) -> ()>,
    pub load_from_file: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                                    _: *mut libc::c_char)
                                   -> afl_ret_t>,
    pub save_to_file: Option<unsafe extern "C" fn(_: *mut afl_input_t,
                                                  _: *mut libc::c_char)
                                 -> afl_ret_t>,
    pub clear: Option<unsafe extern "C" fn(_: *mut afl_input_t) -> ()>,
    pub get_bytes: Option<unsafe extern "C" fn(_: *mut afl_input_t)
                              -> *mut u8_0>,
    pub delete: Option<unsafe extern "C" fn(_: *mut afl_input_t) -> ()>,
}
pub type afl_input_t = afl_input;
pub type XXH64_hash_t = uint64_t;
pub type xxh_u64 = XXH64_hash_t;
pub type XXH_alignment = libc::c_uint;
pub const XXH_unaligned: XXH_alignment = 1;
pub const XXH_aligned: XXH_alignment = 0;
pub type xxh_u8 = uint8_t;
pub type xxh_u32 = XXH32_hash_t;
pub type XXH32_hash_t = uint32_t;
/* Write the contents of the input to a timeoutfile */
/* Write the contents of the input which causes a crash in the target to a crashfile */
/* Function to create and destroy a new input, allocates memory and initializes
  it. In destroy, it first deinitializes the struct and then frees it. */
#[inline]
unsafe extern "C" fn afl_input_new() -> *mut afl_input_t {
    let mut ret: *mut afl_input_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_input_t>() as libc::c_ulong) as
            *mut afl_input_t;
    if ret.is_null() { return 0 as *mut afl_input_t }
    if afl_input_init(ret) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_input_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_input_delete(mut afl_input: *mut afl_input_t) {
    afl_input_deinit(afl_input);
    free(afl_input as *mut libc::c_void);
}
/*
   american fuzzy lop++ - error-checking, memory-zeroing alloc routines
   --------------------------------------------------------------------

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

   This allocator is not designed to resist malicious attackers (the canaries
   are small and predictable), but provides a robust and portable way to detect
   use-after-free, off-by-one writes, stale pointers, and so on.

 */
/* this file contains anything allocator-realted libafl */
/* Initial size used for afl_realloc */
// Be careful! _WANT_ORIGINAL_AFL_ALLOC is not compatible with custom mutators
// afl++ stuff without memory corruption checks - for speed
/* User-facing macro to sprintf() to a dynamically allocated buffer. */
/* Macro to enforce allocation limits as a last-resort defense against
     integer overflows. */
/* Macro to check malloc() failures and the like. */
/* Allocate a buffer, explicitly not zeroing it. Returns NULL for zero-sized
   requests. */
/* Allocate a buffer, returning zeroed memory. */
/* Free memory, checking for double free and corrupted heap. When DEBUG_BUILD
   is set, the old memory will be also clobbered with 0xFF. */
/* Re-allocate a buffer, checking for issues and zeroing any newly-added tail.
   With DEBUG_BUILD, the buffer is always reallocated to a new addresses and the
   old memory is clobbered with 0xFF. */
/* Catch pointer issues sooner: force relocation and make sure that the
     original buffer is wiped. */
/* Create a buffer with a copy of a string. Returns NULL for NULL inputs. */
/* In non-debug mode, we just do straightforward aliasing of the above
     functions to user-visible names such as ck_alloc(). */
/* _WANT_ORIGINAL_AFL_ALLOC */
/* This function calculates the next power of 2 greater or equal its argument.
 @return The rounded up power of 2 (if no overflow) or 0 on overflow.
*/
// Commented this out as this behavior doesn't change, according to unittests
  // if (in == 0 || in > (size_t)-1) {
//
  //   return 0;                  /* avoid undefined behaviour under-/overflow
  //   */
  //
  // }
/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
/* The complete allocated size, including the header of len
   * AFL_ALLOC_SIZE_OFFSET */
/* Make sure this is an alloc_buf */
/* ptr to the first element of the actual buffer */
/* Returs the container element to this ptr */
/* Gets the maximum size of the buf contents (ptr->complete_size -
 * AFL_ALLOC_SIZE_OFFSET) */
/* This function makes sure *size is > size_needed after call.
 It will realloc *buf otherwise.
 *size will grow exponentially as per:
 https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
 Will return NULL and free *buf if size_needed is <1 or realloc failed.
 @return For convenience, this function returns *buf.
 */
/* the size is always stored at buf - 1*size_t */
/* No need to realloc */
/* No initial size was set */
/* grow exponentially */
/* handle overflow: fall back to the original size_needed */
/* alloc */
#[inline]
unsafe extern "C" fn afl_free(mut buf: *mut libc::c_void) {
    if !buf.is_null() { free(afl_alloc_bufptr(buf) as *mut libc::c_void); };
}
#[inline]
unsafe extern "C" fn next_pow2(mut in_0: size_t) -> size_t {
    let mut out: size_t =
        in_0.wrapping_sub(1 as libc::c_int as libc::c_ulong);
    out |= out >> 1 as libc::c_int;
    out |= out >> 2 as libc::c_int;
    out |= out >> 4 as libc::c_int;
    out |= out >> 8 as libc::c_int;
    out |= out >> 16 as libc::c_int;
    return out.wrapping_add(1 as libc::c_int as libc::c_ulong);
}
#[inline]
unsafe extern "C" fn afl_alloc_bufptr(mut buf: *mut libc::c_void)
 -> *mut afl_alloc_buf {
    return (buf as *mut u8_0).offset(-(16 as libc::c_ulong as isize)) as
               *mut afl_alloc_buf;
}
#[inline]
unsafe extern "C" fn afl_realloc(mut buf: *mut libc::c_void,
                                 mut size_needed: size_t)
 -> *mut libc::c_void {
    let mut new_buf: *mut afl_alloc_buf = 0 as *mut afl_alloc_buf;
    let mut current_size: size_t = 0 as libc::c_int as size_t;
    let mut next_size: size_t = 0 as libc::c_int as size_t;
    if !buf.is_null() {
        new_buf = afl_alloc_bufptr(buf);
        if (*new_buf).magic != 0xaf1a110c as libc::c_uint as libc::c_ulong {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mIllegal, non-null pointer passed to afl_realloc (buf 0x%p, magic 0x%x)\x00"
                       as *const u8 as *const libc::c_char, new_buf,
                   (*new_buf).magic as libc::c_uint);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 12],
                                             &[libc::c_char; 12]>(b"afl_realloc\x00")).as_ptr(),
                   b"include/alloc-inl.h\x00" as *const u8 as
                       *const libc::c_char, 673 as libc::c_int);
            exit(1 as libc::c_int);
        }
        current_size = (*new_buf).complete_size
    }
    size_needed =
        (size_needed as libc::c_ulong).wrapping_add(16 as libc::c_ulong) as
            size_t as size_t;
    if current_size >= size_needed { return buf }
    if size_needed < 64 as libc::c_int as libc::c_ulong {
        next_size = 64 as libc::c_int as size_t
    } else {
        next_size = next_pow2(size_needed);
        if next_size == 0 { next_size = size_needed }
    }
    new_buf =
        realloc(new_buf as *mut libc::c_void, next_size) as
            *mut afl_alloc_buf;
    if new_buf.is_null() { return 0 as *mut libc::c_void }
    (*new_buf).complete_size = next_size;
    (*new_buf).magic = 0xaf1a110c as libc::c_uint as size_t;
    return (*new_buf).buf.as_mut_ptr() as *mut libc::c_void;
}
/*
 * xxHash - Extremely Fast Hash algorithm
 * Header File
 * Copyright (C) 2012-2020 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */
/* TODO: update */
/* Notice extracted from xxHash homepage:

xxHash is an extremely fast hash algorithm, running at RAM speed limits.
It also successfully passes all tests from the SMHasher suite.

Comparison (single thread, Windows Seven 32 bits, using SMHasher on a Core 2 Duo
@3GHz)

Name            Speed       Q.Score   Author
xxHash          5.4 GB/s     10
CrapWow         3.2 GB/s      2       Andrew
MumurHash 3a    2.7 GB/s     10       Austin Appleby
SpookyHash      2.0 GB/s     10       Bob Jenkins
SBox            1.4 GB/s      9       Bret Mulvey
Lookup3         1.2 GB/s      9       Bob Jenkins
SuperFastHash   1.2 GB/s      1       Paul Hsieh
CityHash64      1.05 GB/s    10       Pike & Alakuijala
FNV             0.55 GB/s     5       Fowler, Noll, Vo
CRC32           0.43 GB/s     9
MD5-32          0.33 GB/s    10       Ronald L. Rivest
SHA1-32         0.28 GB/s    10

Q.Score is a measure of quality of the hash function.
It depends on successfully passing SMHasher test set.
10 is a perfect score.

Note: SMHasher's CRC32 implementation is not the fastest one.
Other speed-oriented implementations can be faster,
especially in combination with PCLMUL instruction:
https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html?showComment=1552696407071#c3490092340461170735

A 64-bit version, named XXH64, is available since r35.
It offers much better speed, but for 64-bit applications only.
Name     Speed on 64 bits    Speed on 32 bits
XXH64       13.8 GB/s            1.9 GB/s
XXH32        6.8 GB/s            6.0 GB/s
*/
/* ****************************
 *  INLINE mode
 ******************************/
/* !
 * XXH_INLINE_ALL (and XXH_PRIVATE_API)
 * Use these build macros to inline xxhash into the target unit.
 * Inlining improves performance on small inputs, especially when the length is
 * expressed as a compile-time constant:
 *
 *      https://fastcompression.blogspot.com/2018/03/xxhash-for-small-keys-impressive-power.html
 *
 * It also keeps xxHash symbols private to the unit, so they are not exported.
 *
 * Usage:
 *     #define XXH_INLINE_ALL
 *     #include "xxhash.h"
 *
 * Do not compile and link xxhash.o as a separate object, as it is not useful.
 */
/* this section should be traversed only once */
/* give access to the advanced API, required to compile implementations */
/* avoid macro redef */
/* make all functions private */
/* C99 */
/*
 * This part deals with the special case where a unit wants to inline xxHash,
 * but "xxhash.h" has previously been included without XXH_INLINE_ALL, such
 * as part of some previously included *.h header file.
 * Without further action, the new include would just be ignored,
 * and functions would effectively _not_ be inlined (silent failure).
 * The following macros solve this situation by prefixing all inlined names,
 * avoiding naming collision with previous inclusions.
 */
/*
 * Some identifiers (enums, type names) are not symbols, but they must
 * still be renamed to avoid redeclaration.
 * Alternative solution: do not redeclare them.
 * However, this requires some #ifdefs, and is a more dispersed action.
 * Meanwhile, renaming can be achieved in a single block
 */
/* Ensure the header is parsed again, even if it was previously included */
/* XXH_INLINE_ALL || XXH_PRIVATE_API */
/* ****************************************************************
 *  Stable API
 *****************************************************************/
/* specific declaration modes for Windows */
/* !
   * XXH_NAMESPACE, aka Namespace Emulation:
   *
   * If you want to include _and expose_ xxHash functions from within your own
   * library, but also want to avoid symbol collisions with other libraries
   * which may also include xxHash, you can use XXH_NAMESPACE to automatically
   * prefix any public symbol from xxhash library with the value of
   * XXH_NAMESPACE (therefore, avoid empty or numeric values).
   *
   * Note that no change is required within the calling program as long as it
   * includes `xxhash.h`: Regular symbol names will be automatically translated
   * by this header.
   */
/* *************************************
   *  Version
   ***************************************/
/* ****************************
   *  Definitions
   ******************************/
/* size_t */
/*-**********************************************************************
   *  32-bit hash
   ************************************************************************/
/* C99 */
/* !
 * XXH32():
 *  Calculate the 32-bit hash of sequence "length" bytes stored at memory
 * address "input". The memory between input & input+length must be valid
 * (allocated and read-accessible). "seed" can be used to alter the result
 * predictably. Speed on Core 2 Duo @ 3 GHz (single thread, SMHasher
 * benchmark): 5.4 GB/s
 *
 * Note: XXH3 provides competitive speed for both 32-bit and 64-bit systems,
 * and offers true 64/128 bit hash results. It provides a superior level of
 * dispersion, and greatly reduces the risks of collisions.
 */
/* ******   Streaming   *******/
/*
 * Streaming functions generate the xxHash value from an incrememtal input.
 * This method is slower than single-call functions, due to state management.
 * For small inputs, prefer `XXH32()` and `XXH64()`, which are better optimized.
 *
 * An XXH state must first be allocated using `XXH*_createState()`.
 *
 * Start a new hash by initializing the state with a seed using `XXH*_reset()`.
 *
 * Then, feed the hash state by calling `XXH*_update()` as many times as
 * necessary.
 *
 * The function returns an error code, with 0 meaning OK, and any other value
 * meaning there is an error.
 *
 * Finally, a hash value can be produced anytime, by using `XXH*_digest()`.
 * This function returns the nn-bits hash as an int or long long.
 *
 * It's still possible to continue inserting input into the hash state after a
 * digest, and generate new hash values later on by invoking `XXH*_digest()`.
 *
 * When done, release the state using `XXH*_freeState()`.
 */
/* incomplete type */
/* ******   Canonical representation   *******/
/*
 * The default return values from XXH functions are unsigned 32 and 64 bit
 * integers.
 * This the simplest and fastest format for further post-processing.
 *
 * However, this leaves open the question of what is the order on the byte
 * level, since little and big endian conventions will store the same number
 * differently.
 *
 * The canonical representation settles this issue by mandating big-endian
 * convention, the same convention as human-readable numbers (large digits
 * first).
 *
 * When writing hash values to storage, sending them over a network, or printing
 * them, it's highly recommended to use the canonical representation to ensure
 * portability across a wider range of systems, present and future.
 *
 * The following functions allow transformation of hash values to and from
 * canonical format.
 */
/*-**********************************************************************
     *  64-bit hash
     ************************************************************************/
/* C99 */
/* !
 * XXH64():
 * Returns the 64-bit hash of sequence of length @length stored at memory
 * address @input.
 * @seed can be used to alter the result predictably.
 *
 * This function usually runs faster on 64-bit systems, but slower on 32-bit
 * systems (see benchmark).
 *
 * Note: XXH3 provides competitive speed for both 32-bit and 64-bit systems,
 * and offers true 64/128 bit hash results. It provides a superior level of
 * dispersion, and greatly reduces the risks of collisions.
 */
/* ******   Streaming   *******/
/* incomplete type */
/* ******   Canonical representation   *******/
/* XXH_NO_LONG_LONG */
/* XXHASH_H_5627135585666179 */
/* ****************************************************************************
 * This section contains declarations which are not guaranteed to remain stable.
 * They may change in future versions, becoming incompatible with a different
 * version of the library.
 * These declarations should only be used with static linking.
 * Never use them in association with dynamic linking!
 *****************************************************************************
 */
/*
 * These definitions are only present to allow static allocation of an XXH
 * state, for example, on the stack or in a struct.
 * Never **ever** access members directly.
 */
/* never read nor write, might be removed in a future version */
/* typedef'd to XXH32_state_t */
/* defined when there is no 64-bit support */
/* required for padding anyway */
/* never read nor write, might be removed in a future
                              version */
/* typedef'd to XXH64_state_t */
/*-**********************************************************************
   *  XXH3
   *  New experimental hash
   ************************************************************************/
/* ************************************************************************
   * XXH3 is a new hash algorithm featuring:
   *  - Improved speed for both small and large inputs
   *  - True 64-bit and 128-bit outputs
   *  - SIMD acceleration
   *  - Improved 32-bit viability
   *
   * Speed analysis methodology is explained here:
   *
   *    https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html
   *
   * In general, expect XXH3 to run about ~2x faster on large inputs and >3x
   * faster on small ones compared to XXH64, though exact differences depend on
   * the platform.
   *
   * The algorithm is portable: Like XXH32 and XXH64, it generates the same hash
   * on all platforms.
   *
   * It benefits greatly from SIMD and 64-bit arithmetic, but does not require
   * it.
   *
   * Almost all 32-bit and 64-bit targets that can run XXH32 smoothly can run
   * XXH3 at competitive speeds, even if XXH64 runs slowly. Further details are
   * explained in the implementation.
   *
   * Optimized implementations are provided for AVX512, AVX2, SSE2, NEON,
   * POWER8, ZVector and scalar targets. This can be controlled with the
   * XXH_VECTOR macro.
   *
   * XXH3 offers 2 variants, _64bits and _128bits.
   * When only 64 bits are needed, prefer calling the _64bits variant, as it
   * reduces the amount of mixing, resulting in faster speed on small inputs.
   *
   * It's also generally simpler to manipulate a scalar return type than a
   * struct.
   *
   * The 128-bit version adds additional strength, but it is slightly slower.
   *
   * The XXH3 algorithm is still in development.
   * The results it produces may still change in future versions.
   *
   * Results produced by v0.7.x are not comparable with results from v0.7.y.
   * However, the API is completely stable, and it can safely be used for
   * ephemeral data (local sessions).
   *
   * Avoid storing values in long-term storage until the algorithm is finalized.
   *
   * Since v0.7.3, XXH3 has reached "release candidate" status, meaning that, if
   * everything remains fine, its current format will be "frozen" and become the
   * final one.
   *
   * After which, return values of XXH3 and XXH128 will no longer change in
   * future versions.
   *
   * XXH3's return values will be officially finalized upon reaching v0.8.0.
   *
   * The API supports one-shot hashing, streaming mode, and custom secrets.
   */
/* XXH3_64bits():
 * default 64-bit variant, using default secret and default seed of 0.
 * It's the fastest variant. */
/*
 * XXH3_64bits_withSeed():
 * This variant generates a custom secret on the fly based on the default
 * secret, altered using the `seed` value.
 * While this operation is decently fast, note that it's not completely free.
 * Note: seed==0 produces the same results as XXH3_64bits().
 */
/*
     * XXH3_64bits_withSecret():
     * It's possible to provide any blob of bytes as a "secret" to generate the
     * hash. This makes it more difficult for an external actor to prepare an
     * intentional collision. secretSize *must* be large enough (>=
     * XXH3_SECRET_SIZE_MIN). The hash quality depends on the secret's high
     * entropy, meaning that the secret should look like a bunch of random
     * bytes. Avoid "trivial" sequences such as text or a bunch of repeated
     * characters. If you are unsure of the "randonmess" of the blob of bytes,
     * consider making it a "custom seed" instead,
     * and use "XXH_generateSecret()" to generate a high quality secret.
     */
/* streaming 64-bit */
/* C11+ */
/* Old GCC versions only accept the attribute after the type in structures.
     */
/* C11+ */
/* used to store a custom secret generated from a seed */
/* reference to external secret;
                                   * if == NULL, use .customSecret instead */
/* note: there may be some padding at the end due to alignment on 64 bytes */
/* typedef'd to XXH3_state_t */
/*
 * Streaming requires state maintenance.
 * This operation costs memory and CPU.
 * As a consequence, streaming is slower than one-shot hashing.
 * For better performance, prefer one-shot functions whenever possible.
 */
/*
 * XXH3_64bits_reset():
 * Initialize with the default parameters.
 * The result will be equivalent to `XXH3_64bits()`.
 */
/*
 * XXH3_64bits_reset_withSeed():
 * Generate a custom secret from `seed`, and store it into `statePtr`.
 * digest will be equivalent to `XXH3_64bits_withSeed()`.
 */
/*
 * XXH3_64bits_reset_withSecret():
 * `secret` is referenced, and must outlive the hash streaming session, so
 * be careful when using stack arrays.
 * `secretSize` must be >= `XXH3_SECRET_SIZE_MIN`.
 */
/* 128-bit */
/* == XXH128() */
/* Note: For better performance, these functions can be inlined using
 * XXH_INLINE_ALL */
/* !
 * XXH128_isEqual():
 * Return: 1 if `h1` and `h2` are equal, 0 if they are not.
 */
/* !
 * XXH128_cmp():
 *
 * This comparator is compatible with stdlib's `qsort()`/`bsearch()`.
 *
 * return: >0 if *h128_1  > *h128_2
 *         =0 if *h128_1 == *h128_2
 *         <0 if *h128_1  < *h128_2
 */
/* ******   Canonical representation   *******/
/* ===   Experimental API   === */
/* Symbols defined below must be considered tied to a specific library version.
 */
/*
 * XXH3_generateSecret():
 *
 * Derive a secret for use with `*_withSecret()` prototypes of XXH3.
 * Use this if you need a higher level of security than the one provided by
 * 64bit seed.
 *
 * Take as input a custom seed of any length and any content,
 * generate from it a high-entropy secret of length XXH3_SECRET_DEFAULT_SIZE
 * into already allocated buffer secretBuffer.
 * The generated secret ALWAYS is XXH_SECRET_DEFAULT_SIZE bytes long.
 *
 * The generated secret can then be used with any `*_withSecret()` variant.
 * The functions `XXH3_128bits_withSecret()`, `XXH3_64bits_withSecret()`,
 * `XXH3_128bits_reset_withSecret()` and `XXH3_64bits_reset_withSecret()`
 * are part of this list. They all accept a `secret` parameter
 * which must be very long for implementation reasons (>= XXH3_SECRET_SIZE_MIN)
 * _and_ feature very high entropy (consist of random-looking bytes).
 * These conditions can be a high bar to meet, so
 * this function can be used to generate a secret of proper quality.
 *
 * customSeed can be anything. It can have any size, even small ones,
 * and its content can be anything, even some "low entropy" source such as a
 * bunch of zeroes. The resulting `secret` will nonetheless respect all expected
 * qualities.
 *
 * Supplying NULL as the customSeed copies the default secret into
 * `secretBuffer`. When customSeedSize > 0, supplying NULL as customSeed is
 * undefined behavior.
 */
/* XXH_NO_LONG_LONG */
/* defined(XXH_STATIC_LINKING_ONLY) && \
          !defined(XXHASH_H_STATIC_13879238742) */
/* ======================================================================== */
/* ======================================================================== */
/* ======================================================================== */
/*-**********************************************************************
 * xxHash implementation
 *-**********************************************************************
 * xxHash's implementation used to be found in xxhash.c.
 *
 * However, code inlining requires the implementation to be visible to the
 * compiler, usually within the header.
 *
 * As a workaround, xxhash.c used to be included within xxhash.h. This caused
 * some issues with some build systems, especially ones which treat .c files
 * as source files.
 *
 * Therefore, the implementation is now directly integrated within xxhash.h.
 * Another small advantage is that xxhash.c is no longer needed in /include.
 ************************************************************************/
/* *************************************
   *  Tuning parameters
   ***************************************/
  /* !
   * XXH_FORCE_MEMORY_ACCESS:
   * By default, access to unaligned memory is controlled by `memcpy()`, which
   * is safe and portable.
   *
   * Unfortunately, on some target/compiler combinations, the generated assembly
   * is sub-optimal.
   *
   * The below switch allow to select a different access method for improved
   * performance.
   * Method 0 (default):
   *     Use `memcpy()`. Safe and portable.
   * Method 1:
   *     `__attribute__((packed))` statement. It depends on compiler extensions
   *     and is therefore not portable.
   *     This method is safe if your compiler supports it, and *generally* as
   *     fast or faster than `memcpy`.
   * Method 2:
   *     Direct access via cast. This method doesn't depend on the compiler but
   *     violates the C standard.
   *     It can generate buggy code on targets which do not support unaligned
   *     memory accesses.
   *     But in some circumstances, it's the only known way to get the most
   *     performance (ie GCC + ARMv6)
   * Method 3:
   *     Byteshift. This can generate the best code on old compilers which don't
   *     inline small `memcpy()` calls, and it might also be faster on
   * big-endian systems which lack a native byteswap instruction. See
   * https://stackoverflow.com/a/32095106/646947 for details. Prefer these
   * methods in priority order (0 > 1 > 2 > 3)
   */
/* can be defined externally, on command \
                                     line for example */
/* !
   * XXH_ACCEPT_NULL_INPUT_POINTER:
   * If the input pointer is NULL, xxHash's default behavior is to dereference
   * it, triggering a segfault. When this macro is enabled, xxHash actively
   * checks the input for a null pointer. If it is, the result for null input
   * pointers is the same as a zero-length input.
   */
/* can be defined externally */
/* !
   * XXH_FORCE_ALIGN_CHECK:
   * This is an important performance trick
   * for architectures without decent unaligned memory access performance.
   * It checks for input alignment, and when conditions are met,
   * uses a "fast path" employing direct 32-bit/64-bit read,
   * resulting in _dramatically faster_ read speed.
   *
   * The check costs one initial branch per hash, which is generally negligible,
   * but not zero. Moreover, it's not useful to generate binary for an
   * additional code path if memory access uses same instruction for both
   * aligned and unaligned adresses.
   *
   * In these cases, the alignment check can be removed by setting this macro to
   * 0. Then the code will always use unaligned memory access. Align check is
   * automatically disabled on x86, x64 & arm64, which are platforms known to
   * offer good unaligned memory accesses performance.
   *
   * This option does not affect XXH3 (only XXH32 and XXH64).
   */
/* can be defined externally */
/* visual */
/* !
   * XXH_NO_INLINE_HINTS:
   *
   * By default, xxHash tries to force the compiler to inline almost all
   * internal functions.
   *
   * This can usually improve performance due to reduced jumping and improved
   * constant folding, but significantly increases the size of the binary which
   * might not be favorable.
   *
   * Additionally, sometimes the forced inlining can be detrimental to
   * performance, depending on the architecture.
   *
   * XXH_NO_INLINE_HINTS marks all internal functions as static, giving the
   * compiler full control on whether to inline or not.
   *
   * When not optimizing (-O0), optimizing for size (-Os, -Oz), or using
   * -fno-inline with GCC or Clang, this will automatically be defined.
   */
/* !
   * XXH_REROLL:
   * Whether to reroll XXH32_finalize, and XXH64_finalize,
   * instead of using an unrolled jump table/if statement loop.
   *
   * This is automatically defined on -Os/-Oz on GCC and Clang.
   */
/* *************************************
   *  Includes & Memory related functions
   ***************************************/
  /* !
   * Modify the local functions below should you wish to use some other memory
   * routines for malloc() and free()
   */
/* ! and for memcpy() */
/* ULLONG_MAX */
/* *************************************
   *  Compiler Specific Options
   ***************************************/
/* Visual Studio warning fix */
/* disable inlining hints */
/* enable inlining hints */
/* Visual Studio */
/* *************************************
   *  Debug
   ***************************************/
  /*
   * XXH_DEBUGLEVEL is expected to be defined externally, typically via the
   * compiler's command line options. The value must be a number.
   */
/* backwards compat */
/* note: use after variable declarations */
/* *************************************
   *  Basic Types
   ***************************************/
/* C99 */
/* ***   Memory access   *** */
/*
 * Portable and safe solution. Generally efficient.
 * see: https://stackoverflow.com/a/32095106/646947
 */
unsafe extern "C" fn XXH_read32(mut memPtr: *const libc::c_void) -> xxh_u32 {
    let mut val: xxh_u32 = 0;
    memcpy(&mut val as *mut xxh_u32 as *mut libc::c_void, memPtr,
           ::std::mem::size_of::<xxh_u32>() as libc::c_ulong);
    return val;
}
/* dummy comment */
/* Compact rerolled version */
/* or switch(bEnd - p) */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* fallthrough */
/* reaching this point is deemed impossible */
/* Input is 4-bytes aligned, leverage the speed benefit */
/* ******   Hash streaming   *******/
/* using a local state to memcpy() in order to avoid
                          strict-aliasing warnings */
/* do not write into reserved, planned to be removed in a future version */
/* fill in tmp buffer */
/* some data left from previous update */
/* == seed */
/* ******   Canonical representation   *******/
/*
 * The default return values from XXH functions are unsigned 32 and 64 bit
 * integers.
 *
 * The canonical representation uses big endian convention, the same convention
 * as human-readable numbers (large digits first).
 *
 * This way, hash values can be written into a file or buffer, remaining
 * comparable across different systems.
 *
 * The following functions allow transformation of hash values to and from their
 * canonical format.
 */
/* *******************************************************************
 *  64-bit hash functions
 *********************************************************************/
/* ******   Memory access   *******/
/* !
     * XXH_REROLL_XXH64:
     * Whether to reroll the XXH64_finalize() loop.
     *
     * Just like XXH32, we can unroll the XXH64_finalize() loop. This can be a
     * performance gain on 64-bit hosts, as only one jump is required.
     *
     * However, on 32-bit hosts, because arithmetic needs to be done with two
     * 32-bit registers, and 64-bit arithmetic needs to be simulated, it isn't
     * beneficial to unroll. The code becomes ridiculously large (the largest
     * function in the binary on i386!), and rerolling it saves anywhere from
     * 3kB to 20kB. It is also slightly faster because it fits into cache better
     * and is more likely to be inlined by the compiler.
     *
     * If XXH_REROLL is defined, this is ignored and the loop is always
     * rerolled.
     */
/* !defined(XXH_REROLL_XXH64) */
/*
 * Portable and safe solution. Generally efficient.
 * see: https://stackoverflow.com/a/32095106/646947
 */
/* XXH_FORCE_DIRECT_MEMORY_ACCESS */
/* Visual Studio */
/* XXH_FORCE_MEMORY_ACCESS==3 is an endian-independent byteshift load. */
/* ******   xxh64   *******/
/* 0b1001111000110111011110011011000110000101111010111100101010000111
                            */
/* 0b1100001010110010101011100011110100100111110101001110101101001111
                            */
/* 0b0001011001010110011001111011000110011110001101110111100111111001
                            */
static mut XXH_PRIME64_4: xxh_u64 =
    0x85ebca77c2b2ae63 as libc::c_ulonglong as xxh_u64;
unsafe extern "C" fn XXH_readLE64_align(mut ptr: *const libc::c_void,
                                        mut align: XXH_alignment) -> xxh_u64 {
    if align as libc::c_uint == XXH_unaligned as libc::c_int as libc::c_uint {
        return XXH_readLE64(ptr)
    } else {
        return if 1 as libc::c_int != 0 {
                   *(ptr as *const xxh_u64)
               } else { XXH_swap64(*(ptr as *const xxh_u64)) }
    };
}
unsafe extern "C" fn XXH_swap64(mut x: xxh_u64) -> xxh_u64 {
    return ((x << 56 as libc::c_int) as libc::c_ulonglong &
                0xff00000000000000 as libc::c_ulonglong |
                (x << 40 as libc::c_int) as libc::c_ulonglong &
                    0xff000000000000 as libc::c_ulonglong |
                (x << 24 as libc::c_int) as libc::c_ulonglong &
                    0xff0000000000 as libc::c_ulonglong |
                (x << 8 as libc::c_int) as libc::c_ulonglong &
                    0xff00000000 as libc::c_ulonglong |
                (x >> 8 as libc::c_int) as libc::c_ulonglong &
                    0xff000000 as libc::c_ulonglong |
                (x >> 24 as libc::c_int) as libc::c_ulonglong &
                    0xff0000 as libc::c_ulonglong |
                (x >> 40 as libc::c_int) as libc::c_ulonglong &
                    0xff00 as libc::c_ulonglong |
                (x >> 56 as libc::c_int) as libc::c_ulonglong &
                    0xff as libc::c_ulonglong) as xxh_u64;
}
unsafe extern "C" fn XXH_readLE64(mut ptr: *const libc::c_void) -> xxh_u64 {
    return if 1 as libc::c_int != 0 {
               XXH_read64(ptr)
           } else { XXH_swap64(XXH_read64(ptr)) };
}
unsafe extern "C" fn XXH_read64(mut memPtr: *const libc::c_void) -> xxh_u64 {
    let mut val: xxh_u64 = 0;
    memcpy(&mut val as *mut xxh_u64 as *mut libc::c_void, memPtr,
           ::std::mem::size_of::<xxh_u64>() as libc::c_ulong);
    return val;
}
unsafe extern "C" fn XXH64_round(mut acc: xxh_u64, mut input: xxh_u64)
 -> xxh_u64 {
    acc =
        (acc as libc::c_ulong).wrapping_add(input.wrapping_mul(XXH_PRIME64_2))
            as xxh_u64 as xxh_u64;
    acc =
        acc << 31 as libc::c_int |
            acc >> 64 as libc::c_int - 31 as libc::c_int;
    acc =
        (acc as libc::c_ulong).wrapping_mul(XXH_PRIME64_1) as xxh_u64 as
            xxh_u64;
    return acc;
}
unsafe extern "C" fn XXH64_mergeRound(mut acc: xxh_u64, mut val: xxh_u64)
 -> xxh_u64 {
    val = XXH64_round(0 as libc::c_int as xxh_u64, val);
    acc ^= val;
    acc = acc.wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
    return acc;
}
static mut XXH_PRIME64_5: xxh_u64 =
    0x27d4eb2f165667c5 as libc::c_ulonglong as xxh_u64;
unsafe extern "C" fn XXH_swap32(mut x: xxh_u32) -> xxh_u32 {
    return x << 24 as libc::c_int & 0xff000000 as libc::c_uint |
               x << 8 as libc::c_int & 0xff0000 as libc::c_int as libc::c_uint
               | x >> 8 as libc::c_int & 0xff00 as libc::c_int as libc::c_uint
               | x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint;
}
unsafe extern "C" fn XXH_readLE32_align(mut ptr: *const libc::c_void,
                                        mut align: XXH_alignment) -> xxh_u32 {
    if align as libc::c_uint == XXH_unaligned as libc::c_int as libc::c_uint {
        return XXH_readLE32(ptr)
    } else {
        return if 1 as libc::c_int != 0 {
                   *(ptr as *const xxh_u32)
               } else { XXH_swap32(*(ptr as *const xxh_u32)) }
    };
}
static mut XXH_PRIME64_1: xxh_u64 =
    0x9e3779b185ebca87 as libc::c_ulonglong as xxh_u64;
static mut XXH_PRIME64_2: xxh_u64 =
    0xc2b2ae3d27d4eb4f as libc::c_ulonglong as xxh_u64;
static mut XXH_PRIME64_3: xxh_u64 =
    0x165667b19e3779f9 as libc::c_ulonglong as xxh_u64;
unsafe extern "C" fn XXH64_avalanche(mut h64: xxh_u64) -> xxh_u64 {
    h64 ^= h64 >> 33 as libc::c_int;
    h64 =
        (h64 as libc::c_ulong).wrapping_mul(XXH_PRIME64_2) as xxh_u64 as
            xxh_u64;
    h64 ^= h64 >> 29 as libc::c_int;
    h64 =
        (h64 as libc::c_ulong).wrapping_mul(XXH_PRIME64_3) as xxh_u64 as
            xxh_u64;
    h64 ^= h64 >> 32 as libc::c_int;
    return h64;
}
unsafe extern "C" fn XXH64_finalize(mut h64: xxh_u64, mut ptr: *const xxh_u8,
                                    mut len: size_t, mut align: XXH_alignment)
 -> xxh_u64 {
    if 0 as libc::c_int != 0 || 0 as libc::c_int != 0 {
        len &= 31 as libc::c_int as libc::c_ulong;
        while len >= 8 as libc::c_int as libc::c_ulong {
            let k1: xxh_u64 =
                XXH64_round(0 as libc::c_int as xxh_u64,
                            XXH_readLE64_align(ptr as *const libc::c_void,
                                               align));
            ptr = ptr.offset(8 as libc::c_int as isize);
            h64 ^= k1;
            h64 =
                (h64 << 27 as libc::c_int |
                     h64 >>
                         64 as libc::c_int -
                             27 as
                                 libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
            len =
                (len as
                     libc::c_ulong).wrapping_sub(8 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t
        }
        if len >= 4 as libc::c_int as libc::c_ulong {
            h64 ^=
                (XXH_readLE32_align(ptr as *const libc::c_void, align) as
                     xxh_u64).wrapping_mul(XXH_PRIME64_1);
            ptr = ptr.offset(4 as libc::c_int as isize);
            h64 =
                (h64 << 23 as libc::c_int |
                     h64 >>
                         64 as libc::c_int -
                             23 as
                                 libc::c_int).wrapping_mul(XXH_PRIME64_2).wrapping_add(XXH_PRIME64_3);
            len =
                (len as
                     libc::c_ulong).wrapping_sub(4 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t
        }
        while len > 0 as libc::c_int as libc::c_ulong {
            let fresh0 = ptr;
            ptr = ptr.offset(1);
            h64 ^= (*fresh0 as libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
            h64 =
                (h64 << 11 as libc::c_int |
                     h64 >>
                         64 as libc::c_int -
                             11 as libc::c_int).wrapping_mul(XXH_PRIME64_1);
            len = len.wrapping_sub(1)
        }
        return XXH64_avalanche(h64)
    } else {
        's_1165:
            {
                let mut current_block_221: u64;
                match len & 31 as libc::c_int as libc::c_ulong {
                    24 => {
                        let k1_0: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_0;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 13996298019017622175;
                    }
                    16 => { current_block_221 = 13996298019017622175; }
                    8 => { current_block_221 = 4608782999795822876; }
                    28 => {
                        let k1_3: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_3;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 16592787104725195690;
                    }
                    20 => { current_block_221 = 16592787104725195690; }
                    12 => { current_block_221 = 17618848808640280019; }
                    4 => { current_block_221 = 14677634444826911261; }
                    25 => {
                        let k1_6: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_6;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 14178492442605508430;
                    }
                    17 => { current_block_221 = 14178492442605508430; }
                    9 => { current_block_221 = 16779975337331038471; }
                    29 => {
                        let k1_9: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_9;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 12031451804993171459;
                    }
                    21 => { current_block_221 = 12031451804993171459; }
                    13 => { current_block_221 = 6754707644581100215; }
                    5 => { current_block_221 = 5461728508594294560; }
                    26 => {
                        let k1_12: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_12;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 9893163535709771494;
                    }
                    18 => { current_block_221 = 9893163535709771494; }
                    10 => { current_block_221 = 40402282971785355; }
                    30 => {
                        let k1_15: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_15;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 15663857331018810243;
                    }
                    22 => { current_block_221 = 15663857331018810243; }
                    14 => { current_block_221 = 8494449151717016192; }
                    6 => { current_block_221 = 15165110314757442493; }
                    27 => {
                        let k1_18: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_18;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 1879630039366599944;
                    }
                    19 => { current_block_221 = 1879630039366599944; }
                    11 => { current_block_221 = 8783088413064093981; }
                    31 => {
                        let k1_21: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_21;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 8345132050669682377;
                    }
                    23 => { current_block_221 = 8345132050669682377; }
                    15 => { current_block_221 = 5146917061243876391; }
                    7 => { current_block_221 = 10206803772969948157; }
                    3 => { current_block_221 = 10119482032545935241; }
                    2 => { current_block_221 = 13022185038212455545; }
                    1 => { current_block_221 = 15498376303259493931; }
                    0 => { current_block_221 = 5905911195108616890; }
                    _ => { break 's_1165 ; }
                }
                match current_block_221 {
                    13996298019017622175 => {
                        let k1_1: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_1;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 4608782999795822876;
                    }
                    16592787104725195690 => {
                        let k1_4: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_4;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 17618848808640280019;
                    }
                    14178492442605508430 => {
                        let k1_7: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_7;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 16779975337331038471;
                    }
                    12031451804993171459 => {
                        let k1_10: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_10;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 6754707644581100215;
                    }
                    9893163535709771494 => {
                        let k1_13: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_13;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 40402282971785355;
                    }
                    15663857331018810243 => {
                        let k1_16: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_16;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 8494449151717016192;
                    }
                    1879630039366599944 => {
                        let k1_19: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_19;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 8783088413064093981;
                    }
                    8345132050669682377 => {
                        let k1_22: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_22;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 5146917061243876391;
                    }
                    _ => { }
                }
                match current_block_221 {
                    8783088413064093981 => {
                        let k1_20: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_20;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        let fresh7 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh7 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        let fresh8 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh8 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        let fresh9 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh9 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        return XXH64_avalanche(h64)
                    }
                    40402282971785355 => {
                        let k1_14: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_14;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        let fresh3 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh3 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        let fresh4 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh4 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        return XXH64_avalanche(h64)
                    }
                    16779975337331038471 => {
                        let k1_8: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_8;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        let fresh1 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh1 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        return XXH64_avalanche(h64)
                    }
                    4608782999795822876 => {
                        let k1_2: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_2;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        return XXH64_avalanche(h64)
                    }
                    17618848808640280019 => {
                        let k1_5: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_5;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 14677634444826911261;
                    }
                    6754707644581100215 => {
                        let k1_11: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_11;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 5461728508594294560;
                    }
                    8494449151717016192 => {
                        let k1_17: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_17;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 15165110314757442493;
                    }
                    5146917061243876391 => {
                        let k1_23: xxh_u64 =
                            XXH64_round(0 as libc::c_int as xxh_u64,
                                        XXH_readLE64_align(ptr as
                                                               *const libc::c_void,
                                                           align));
                        ptr = ptr.offset(8 as libc::c_int as isize);
                        h64 ^= k1_23;
                        h64 =
                            (h64 << 27 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         27 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
                        current_block_221 = 10206803772969948157;
                    }
                    _ => { }
                }
                match current_block_221 {
                    15165110314757442493 => {
                        h64 ^=
                            (XXH_readLE32_align(ptr as *const libc::c_void,
                                                align) as
                                 xxh_u64).wrapping_mul(XXH_PRIME64_1);
                        ptr = ptr.offset(4 as libc::c_int as isize);
                        h64 =
                            (h64 << 23 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         23 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_2).wrapping_add(XXH_PRIME64_3);
                        let fresh5 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh5 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        let fresh6 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh6 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        return XXH64_avalanche(h64)
                    }
                    5461728508594294560 => {
                        h64 ^=
                            (XXH_readLE32_align(ptr as *const libc::c_void,
                                                align) as
                                 xxh_u64).wrapping_mul(XXH_PRIME64_1);
                        ptr = ptr.offset(4 as libc::c_int as isize);
                        h64 =
                            (h64 << 23 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         23 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_2).wrapping_add(XXH_PRIME64_3);
                        let fresh2 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh2 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        return XXH64_avalanche(h64)
                    }
                    14677634444826911261 => {
                        h64 ^=
                            (XXH_readLE32_align(ptr as *const libc::c_void,
                                                align) as
                                 xxh_u64).wrapping_mul(XXH_PRIME64_1);
                        ptr = ptr.offset(4 as libc::c_int as isize);
                        h64 =
                            (h64 << 23 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         23 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_2).wrapping_add(XXH_PRIME64_3);
                        return XXH64_avalanche(h64)
                    }
                    10206803772969948157 => {
                        h64 ^=
                            (XXH_readLE32_align(ptr as *const libc::c_void,
                                                align) as
                                 xxh_u64).wrapping_mul(XXH_PRIME64_1);
                        ptr = ptr.offset(4 as libc::c_int as isize);
                        h64 =
                            (h64 << 23 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         23 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_2).wrapping_add(XXH_PRIME64_3);
                        current_block_221 = 10119482032545935241;
                    }
                    _ => { }
                }
                match current_block_221 {
                    10119482032545935241 => {
                        let fresh10 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh10 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        current_block_221 = 13022185038212455545;
                    }
                    _ => { }
                }
                match current_block_221 {
                    13022185038212455545 => {
                        let fresh11 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh11 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        current_block_221 = 15498376303259493931;
                    }
                    _ => { }
                }
                match current_block_221 {
                    15498376303259493931 => {
                        let fresh12 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh12 as
                                 libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
                        h64 =
                            (h64 << 11 as libc::c_int |
                                 h64 >>
                                     64 as libc::c_int -
                                         11 as
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1)
                    }
                    _ => { }
                }
                return XXH64_avalanche(h64)
            }
    }
    return 0 as libc::c_int as xxh_u64;
}
unsafe extern "C" fn XXH64_endian_align(mut input: *const xxh_u8,
                                        mut len: size_t, mut seed: xxh_u64,
                                        mut align: XXH_alignment) -> xxh_u64 {
    let mut bEnd: *const xxh_u8 = input.offset(len as isize);
    let mut h64: xxh_u64 = 0;
    if len >= 32 as libc::c_int as libc::c_ulong {
        let limit: *const xxh_u8 = bEnd.offset(-(32 as libc::c_int as isize));
        let mut v1: xxh_u64 =
            seed.wrapping_add(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_2);
        let mut v2: xxh_u64 = seed.wrapping_add(XXH_PRIME64_2);
        let mut v3: xxh_u64 =
            seed.wrapping_add(0 as libc::c_int as libc::c_ulong);
        let mut v4: xxh_u64 = seed.wrapping_sub(XXH_PRIME64_1);
        loop  {
            v1 =
                XXH64_round(v1,
                            XXH_readLE64_align(input as *const libc::c_void,
                                               align));
            input = input.offset(8 as libc::c_int as isize);
            v2 =
                XXH64_round(v2,
                            XXH_readLE64_align(input as *const libc::c_void,
                                               align));
            input = input.offset(8 as libc::c_int as isize);
            v3 =
                XXH64_round(v3,
                            XXH_readLE64_align(input as *const libc::c_void,
                                               align));
            input = input.offset(8 as libc::c_int as isize);
            v4 =
                XXH64_round(v4,
                            XXH_readLE64_align(input as *const libc::c_void,
                                               align));
            input = input.offset(8 as libc::c_int as isize);
            if !(input <= limit) { break ; }
        }
        h64 =
            (v1 << 1 as libc::c_int |
                 v1 >>
                     64 as libc::c_int -
                         1 as
                             libc::c_int).wrapping_add(v2 << 7 as libc::c_int
                                                           |
                                                           v2 >>
                                                               64 as
                                                                   libc::c_int
                                                                   -
                                                                   7 as
                                                                       libc::c_int).wrapping_add(v3
                                                                                                     <<
                                                                                                     12
                                                                                                         as
                                                                                                         libc::c_int
                                                                                                     |
                                                                                                     v3
                                                                                                         >>
                                                                                                         64
                                                                                                             as
                                                                                                             libc::c_int
                                                                                                             -
                                                                                                             12
                                                                                                                 as
                                                                                                                 libc::c_int).wrapping_add(v4
                                                                                                                                               <<
                                                                                                                                               18
                                                                                                                                                   as
                                                                                                                                                   libc::c_int
                                                                                                                                               |
                                                                                                                                               v4
                                                                                                                                                   >>
                                                                                                                                                   64
                                                                                                                                                       as
                                                                                                                                                       libc::c_int
                                                                                                                                                       -
                                                                                                                                                       18
                                                                                                                                                           as
                                                                                                                                                           libc::c_int);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4)
    } else { h64 = seed.wrapping_add(XXH_PRIME64_5) }
    h64 = (h64 as libc::c_ulong).wrapping_add(len) as xxh_u64 as xxh_u64;
    return XXH64_finalize(h64, input, len, align);
}
#[inline]
unsafe extern "C" fn XXH_INLINE_XXH64(mut input: *const libc::c_void,
                                      mut len: size_t, mut seed: XXH64_hash_t)
 -> XXH64_hash_t {
    return XXH64_endian_align(input as *const xxh_u8, len, seed,
                              XXH_unaligned);
}
unsafe extern "C" fn XXH_readLE32(mut ptr: *const libc::c_void) -> xxh_u32 {
    return if 1 as libc::c_int != 0 {
               XXH_read32(ptr)
           } else { XXH_swap32(XXH_read32(ptr)) };
}
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
// Raw input bytes
// Length of the input
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
#[no_mangle]
pub unsafe extern "C" fn afl_input_init(mut input: *mut afl_input_t)
 -> afl_ret_t {
    (*input).funcs.clear =
        Some(afl_input_clear as
                 unsafe extern "C" fn(_: *mut afl_input_t) -> ());
    (*input).funcs.copy =
        Some(afl_input_copy as
                 unsafe extern "C" fn(_: *mut afl_input_t)
                     -> *mut afl_input_t);
    (*input).funcs.deserialize =
        Some(afl_input_deserialize as
                 unsafe extern "C" fn(_: *mut afl_input_t, _: *mut u8_0,
                                      _: size_t) -> ());
    (*input).funcs.get_bytes =
        Some(afl_input_get_bytes as
                 unsafe extern "C" fn(_: *mut afl_input_t) -> *mut u8_0);
    (*input).funcs.load_from_file =
        Some(afl_input_load_from_file as
                 unsafe extern "C" fn(_: *mut afl_input_t,
                                      _: *mut libc::c_char) -> afl_ret_t);
    (*input).funcs.restore =
        Some(afl_input_restore as
                 unsafe extern "C" fn(_: *mut afl_input_t,
                                      _: *mut afl_input_t) -> ());
    (*input).funcs.save_to_file =
        Some(afl_input_write_to_file as
                 unsafe extern "C" fn(_: *mut afl_input_t,
                                      _: *mut libc::c_char) -> afl_ret_t);
    (*input).funcs.serialize =
        Some(afl_input_serialize as
                 unsafe extern "C" fn(_: *mut afl_input_t) -> *mut u8_0);
    (*input).funcs.delete =
        Some(afl_input_delete as
                 unsafe extern "C" fn(_: *mut afl_input_t) -> ());
    (*input).copy_buf = 0 as *mut u8_0;
    (*input).bytes = 0 as *mut u8_0;
    (*input).len = 0 as libc::c_int as size_t;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_deinit(mut input: *mut afl_input_t) {
    /* Deiniting requires a little hack. We free the byte ONLY if copy buf is not NULL. Because then we can assume that
   * the input is in the queue*/
    if !(*input).bytes.is_null() && !(*input).copy_buf.is_null() {
        free((*input).bytes as *mut libc::c_void);
        afl_free((*input).copy_buf as *mut libc::c_void);
    }
    (*input).bytes = 0 as *mut u8_0;
    (*input).len = 0 as libc::c_int as size_t;
}
// default implemenatations for the vtable functions for the raw_input type
#[no_mangle]
pub unsafe extern "C" fn afl_input_clear(mut input: *mut afl_input_t) {
    memset((*input).bytes as *mut libc::c_void, 0 as libc::c_int,
           (*input).len);
    (*input).len = 0 as libc::c_int as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_copy(mut orig_inp: *mut afl_input_t)
 -> *mut afl_input_t {
    let mut copy_inp: *mut afl_input_t = afl_input_new();
    if copy_inp.is_null() { return 0 as *mut afl_input_t }
    (*copy_inp).bytes =
        afl_realloc((*orig_inp).copy_buf as *mut libc::c_void,
                    (*orig_inp).len.wrapping_mul(::std::mem::size_of::<u8_0>()
                                                     as libc::c_ulong)) as
            *mut u8_0;
    (*orig_inp).copy_buf = (*copy_inp).bytes;
    if (*copy_inp).bytes.is_null() {
        afl_input_delete(copy_inp);
        return 0 as *mut afl_input_t
    }
    memcpy((*copy_inp).bytes as *mut libc::c_void,
           (*orig_inp).bytes as *const libc::c_void, (*orig_inp).len);
    (*copy_inp).len = (*orig_inp).len;
    return copy_inp;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_deserialize(mut input: *mut afl_input_t,
                                               mut bytes: *mut u8_0,
                                               mut len: size_t) {
    if !(*input).bytes.is_null() {
        free((*input).bytes as *mut libc::c_void);
    }
    (*input).bytes = bytes;
    (*input).len = len;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_get_bytes(mut input: *mut afl_input_t)
 -> *mut u8_0 {
    return (*input).bytes;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_load_from_file(mut input: *mut afl_input_t,
                                                  mut fname:
                                                      *mut libc::c_char)
 -> afl_ret_t {
    let mut st: stat =
        stat{st_dev: 0,
             st_ino: 0,
             st_nlink: 0,
             st_mode: 0,
             st_uid: 0,
             st_gid: 0,
             __pad0: 0,
             st_rdev: 0,
             st_size: 0,
             st_blksize: 0,
             st_blocks: 0,
             st_atim: timespec{tv_sec: 0, tv_nsec: 0,},
             st_mtim: timespec{tv_sec: 0, tv_nsec: 0,},
             st_ctim: timespec{tv_sec: 0, tv_nsec: 0,},
             __glibc_reserved: [0; 3],};
    let mut fd: s32 = open(fname, 0 as libc::c_int);
    if fd < 0 as libc::c_int { return AFL_RET_FILE_OPEN_ERROR }
    if fstat(fd, &mut st) != 0 || st.st_size == 0 {
        close(fd);
        return AFL_RET_FILE_SIZE
    }
    (*input).len = st.st_size as size_t;
    (*input).bytes =
        calloc((*input).len.wrapping_add(1 as libc::c_int as libc::c_ulong),
               1 as libc::c_int as libc::c_ulong) as *mut u8_0;
    if (*input).bytes.is_null() { close(fd); return AFL_RET_ALLOC }
    let mut ret: ssize_t =
        read(fd, (*input).bytes as *mut libc::c_void, (*input).len);
    close(fd);
    if ret < 0 as libc::c_int as libc::c_long || ret as size_t != (*input).len
       {
        free((*input).bytes as *mut libc::c_void);
        (*input).bytes = 0 as *mut u8_0;
        return AFL_RET_SHORT_READ
    }
    return AFL_RET_SUCCESS;
}
// Default implementations of the functions for raw input vtable
/* Write the contents of the input to a file at the given loc */
#[no_mangle]
pub unsafe extern "C" fn afl_input_write_to_file(mut input: *mut afl_input_t,
                                                 mut fname: *mut libc::c_char)
 -> afl_ret_t {
    // if it already exists we will not overwrite it
    if access(fname, 2 as libc::c_int) == 0 as libc::c_int {
        return AFL_RET_FILE_DUPLICATE
    }
    let mut fd: s32 =
        open(fname,
             0o2 as libc::c_int | 0o100 as libc::c_int | 0o200 as libc::c_int,
             0o600 as libc::c_int);
    if fd < 0 as libc::c_int { return AFL_RET_FILE_OPEN_ERROR }
    let mut write_len: ssize_t =
        write(fd, (*input).bytes as *const libc::c_void, (*input).len);
    close(fd);
    if write_len < (*input).len as ssize_t { return AFL_RET_SHORT_WRITE }
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_restore(mut input: *mut afl_input_t,
                                           mut new_inp: *mut afl_input_t) {
    (*input).bytes = (*new_inp).bytes;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_serialize(mut input: *mut afl_input_t)
 -> *mut u8_0 {
    // Very stripped down implementation, actually depends on user alot.
    return (*input).bytes;
}
#[no_mangle]
pub unsafe extern "C" fn afl_input_dump_to_file(mut filetag:
                                                    *mut libc::c_char,
                                                mut data: *mut afl_input_t,
                                                mut directory:
                                                    *mut libc::c_char)
 -> afl_ret_t {
    let mut filename: [libc::c_char; 4096] = [0; 4096];
    /* TODO: This filename should be replaced by "crashes-SHA_OF_BYTES" later */
    let mut input_data_checksum: u64_0 =
        XXH_INLINE_XXH64((*data).bytes as *const libc::c_void, (*data).len,
                         0xa5b35705 as libc::c_uint as XXH64_hash_t) as u64_0;
    if !directory.is_null() {
        snprintf(filename.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 4096]>() as
                     libc::c_ulong,
                 b"%s/%s-%016llx\x00" as *const u8 as *const libc::c_char,
                 directory, filetag, input_data_checksum);
    } else {
        snprintf(filename.as_mut_ptr(),
                 ::std::mem::size_of::<[libc::c_char; 4096]>() as
                     libc::c_ulong,
                 b"%s-%016llx\x00" as *const u8 as *const libc::c_char,
                 filetag, input_data_checksum);
    }
    return afl_input_write_to_file(data, filename.as_mut_ptr());
}
// Timeout related functions
#[no_mangle]
pub unsafe extern "C" fn afl_input_dump_to_timeoutfile(mut data:
                                                           *mut afl_input_t,
                                                       mut directory:
                                                           *mut libc::c_char)
 -> afl_ret_t {
    return afl_input_dump_to_file(b"timeout\x00" as *const u8 as
                                      *const libc::c_char as
                                      *mut libc::c_char, data, directory);
}
// Crash related functions
#[no_mangle]
pub unsafe extern "C" fn afl_input_dump_to_crashfile(mut data:
                                                         *mut afl_input_t,
                                                     mut directory:
                                                         *mut libc::c_char)
 -> afl_ret_t {
    return afl_input_dump_to_file(b"crash\x00" as *const u8 as
                                      *const libc::c_char as
                                      *mut libc::c_char, data, directory);
}
