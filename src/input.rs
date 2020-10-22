use ::libc;
extern "C" {
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn __fxstat(__ver: libc::c_int, __fildes: libc::c_int,
                __stat_buf: *mut stat) -> libc::c_int;
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
/*
   american fuzzy lop++ - type definitions and minor macros
   --------------------------------------------------------

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
pub type u8_0 = uint8_t;
/* Extended forkserver option values */
/* Reporting errors */
/* Reporting options */
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
pub type u64_0 = libc::c_ulonglong;
pub type s32 = int32_t;
/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
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
#[inline]
unsafe extern "C" fn fstat(mut __fd: libc::c_int, mut __statbuf: *mut stat)
 -> libc::c_int {
    return __fxstat(1 as libc::c_int, __fd, __statbuf);
}
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
/* In non-debug mode, we just do straightforward aliasing of the above
     functions to user-visible names such as ck_alloc(). */
/* _WANT_ORIGINAL_AFL_ALLOC */
/* This function calculates the next power of 2 greater or equal its argument.
 @return The rounded up power of 2 (if no overflow) or 0 on overflow.
*/
#[inline]
unsafe extern "C" fn next_pow2(mut in_0: size_t) -> size_t {
    // Commented this out as this behavior doesn't change, according to unittests
  // if (in == 0 || in > (size_t)-1) {
    //
  //   return 0;                  /* avoid undefined behaviour under-/overflow
  //   */
  //
  // }
    let mut out: size_t =
        in_0.wrapping_sub(1 as libc::c_int as libc::c_ulong);
    out |= out >> 1 as libc::c_int;
    out |= out >> 2 as libc::c_int;
    out |= out >> 4 as libc::c_int;
    out |= out >> 8 as libc::c_int;
    out |= out >> 16 as libc::c_int;
    return out.wrapping_add(1 as libc::c_int as libc::c_ulong);
}
/* Returs the container element to this ptr */
#[inline]
unsafe extern "C" fn afl_alloc_bufptr(mut buf: *mut libc::c_void)
 -> *mut afl_alloc_buf {
    return (buf as *mut u8_0).offset(-(16 as libc::c_ulong as isize)) as
               *mut afl_alloc_buf;
}
/* This function makes sure *size is > size_needed after call.
 It will realloc *buf otherwise.
 *size will grow exponentially as per:
 https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
 Will return NULL and free *buf if size_needed is <1 or realloc failed.
 @return For convenience, this function returns *buf.
 */
#[inline]
unsafe extern "C" fn afl_realloc(mut buf: *mut libc::c_void,
                                 mut size_needed: size_t)
 -> *mut libc::c_void {
    let mut new_buf: *mut afl_alloc_buf = 0 as *mut afl_alloc_buf;
    let mut current_size: size_t = 0 as libc::c_int as size_t;
    let mut next_size: size_t = 0 as libc::c_int as size_t;
    if !buf.is_null() {
        /* the size is always stored at buf - 1*size_t */
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
    /* No need to realloc */
    if current_size >= size_needed { return buf }
    /* No initial size was set */
    if size_needed < 64 as libc::c_int as libc::c_ulong {
        next_size = 64 as libc::c_int as size_t
    } else {
        /* grow exponentially */
        next_size = next_pow2(size_needed);
        /* handle overflow: fall back to the original size_needed */
        if next_size == 0 { next_size = size_needed }
    }
    /* alloc */
    new_buf =
        realloc(new_buf as *mut libc::c_void, next_size) as
            *mut afl_alloc_buf;
    if new_buf.is_null() { return 0 as *mut libc::c_void }
    (*new_buf).complete_size = next_size;
    (*new_buf).magic = 0xaf1a110c as libc::c_uint as size_t;
    return (*new_buf).buf.as_mut_ptr() as *mut libc::c_void;
}
#[inline]
unsafe extern "C" fn afl_free(mut buf: *mut libc::c_void) {
    if !buf.is_null() { free(afl_alloc_bufptr(buf) as *mut libc::c_void); };
}
static mut XXH_PRIME64_4: xxh_u64 =
    0x85ebca77c2b2ae63 as libc::c_ulonglong as xxh_u64;
unsafe extern "C" fn XXH64_mergeRound(mut acc: xxh_u64, mut val: xxh_u64)
 -> xxh_u64 {
    val = XXH64_round(0 as libc::c_int as xxh_u64, val);
    acc ^= val;
    acc = acc.wrapping_mul(XXH_PRIME64_1).wrapping_add(XXH_PRIME64_4);
    return acc;
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
unsafe extern "C" fn XXH_read64(mut memPtr: *const libc::c_void) -> xxh_u64 {
    let mut val: xxh_u64 = 0;
    memcpy(&mut val as *mut xxh_u64 as *mut libc::c_void, memPtr,
           ::std::mem::size_of::<xxh_u64>() as libc::c_ulong);
    return val;
}
#[inline(always)]
unsafe extern "C" fn XXH_readLE64(mut ptr: *const libc::c_void) -> xxh_u64 {
    return if 1 as libc::c_int != 0 {
               XXH_read64(ptr)
           } else { XXH_swap64(XXH_read64(ptr)) };
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
#[inline(always)]
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
unsafe extern "C" fn XXH_read32(mut memPtr: *const libc::c_void) -> xxh_u32 {
    let mut val: xxh_u32 = 0;
    memcpy(&mut val as *mut xxh_u32 as *mut libc::c_void, memPtr,
           ::std::mem::size_of::<xxh_u32>() as libc::c_ulong);
    return val;
}
#[inline(always)]
unsafe extern "C" fn XXH_readLE32(mut ptr: *const libc::c_void) -> xxh_u32 {
    return if 1 as libc::c_int != 0 {
               XXH_read32(ptr)
           } else { XXH_swap32(XXH_read32(ptr)) };
}
unsafe extern "C" fn XXH_swap32(mut x: xxh_u32) -> xxh_u32 {
    return x << 24 as libc::c_int & 0xff000000 as libc::c_uint |
               x << 8 as libc::c_int & 0xff0000 as libc::c_int as libc::c_uint
               | x >> 8 as libc::c_int & 0xff00 as libc::c_int as libc::c_uint
               | x >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint;
}
#[inline(always)]
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
static mut XXH_PRIME64_5: xxh_u64 =
    0x27d4eb2f165667c5 as libc::c_ulonglong as xxh_u64;
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
                        current_block_221 = 10959499642475820873;
                    }
                    16 => { current_block_221 = 10959499642475820873; }
                    8 => { current_block_221 = 8676058435761154567; }
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
                        current_block_221 = 9331740632002569930;
                    }
                    20 => { current_block_221 = 9331740632002569930; }
                    12 => { current_block_221 = 13741404658287514157; }
                    4 => { current_block_221 = 12224826967703495742; }
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
                        current_block_221 = 8336624028955672641;
                    }
                    17 => { current_block_221 = 8336624028955672641; }
                    9 => { current_block_221 = 8429548011831789679; }
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
                        current_block_221 = 15771348503364284832;
                    }
                    21 => { current_block_221 = 15771348503364284832; }
                    13 => { current_block_221 = 6078090543149107109; }
                    5 => { current_block_221 = 17615007574301030357; }
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
                        current_block_221 = 8731686057995404305;
                    }
                    18 => { current_block_221 = 8731686057995404305; }
                    10 => { current_block_221 = 14173783181367162198; }
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
                        current_block_221 = 15378266182679408113;
                    }
                    22 => { current_block_221 = 15378266182679408113; }
                    14 => { current_block_221 = 16235676682397023213; }
                    6 => { current_block_221 = 3145606906544522259; }
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
                        current_block_221 = 2702020578203016256;
                    }
                    19 => { current_block_221 = 2702020578203016256; }
                    11 => { current_block_221 = 14534249800322773079; }
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
                        current_block_221 = 5254295861579582150;
                    }
                    23 => { current_block_221 = 5254295861579582150; }
                    15 => { current_block_221 = 2450503316515849410; }
                    7 => { current_block_221 = 3365839365892945652; }
                    3 => { current_block_221 = 11900201696594556385; }
                    2 => { current_block_221 = 17739797279777615877; }
                    1 => { current_block_221 = 18387791726498337928; }
                    0 => { current_block_221 = 1887508248647769826; }
                    _ => { break 's_1165 ; }
                }
                match current_block_221 {
                    10959499642475820873 => {
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
                        current_block_221 = 8676058435761154567;
                    }
                    9331740632002569930 => {
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
                        current_block_221 = 13741404658287514157;
                    }
                    8336624028955672641 => {
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
                        current_block_221 = 8429548011831789679;
                    }
                    15771348503364284832 => {
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
                        current_block_221 = 6078090543149107109;
                    }
                    8731686057995404305 => {
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
                        current_block_221 = 14173783181367162198;
                    }
                    15378266182679408113 => {
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
                        current_block_221 = 16235676682397023213;
                    }
                    2702020578203016256 => {
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
                        current_block_221 = 14534249800322773079;
                    }
                    5254295861579582150 => {
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
                        current_block_221 = 2450503316515849410;
                    }
                    _ => { }
                }
                match current_block_221 {
                    14534249800322773079 => {
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
                    14173783181367162198 => {
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
                    8429548011831789679 => {
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
                    8676058435761154567 => {
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
                    13741404658287514157 => {
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
                        current_block_221 = 12224826967703495742;
                    }
                    6078090543149107109 => {
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
                        current_block_221 = 17615007574301030357;
                    }
                    16235676682397023213 => {
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
                        current_block_221 = 3145606906544522259;
                    }
                    2450503316515849410 => {
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
                        current_block_221 = 3365839365892945652;
                    }
                    _ => { }
                }
                match current_block_221 {
                    3145606906544522259 => {
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
                    17615007574301030357 => {
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
                    12224826967703495742 => {
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
                    3365839365892945652 => {
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
                        current_block_221 = 11900201696594556385;
                    }
                    _ => { }
                }
                match current_block_221 {
                    11900201696594556385 => {
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
                        current_block_221 = 17739797279777615877;
                    }
                    _ => { }
                }
                match current_block_221 {
                    17739797279777615877 => {
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
                        current_block_221 = 18387791726498337928;
                    }
                    _ => { }
                }
                match current_block_221 {
                    18387791726498337928 => {
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
#[inline(always)]
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
