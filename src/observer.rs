use ::libc;
extern "C" {
    pub type afl_engine;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    // Functions to create Shared memory region, for observation channels and
// opening inputs and stuff.
    #[no_mangle]
    fn afl_shmem_init(sharedmem: *mut afl_shmem_t, map_size: size_t)
     -> *mut u8_0;
    #[no_mangle]
    fn afl_shmem_deinit(sharedmem: *mut afl_shmem_t);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type size_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub type u32_0 = uint32_t;
pub type afl_engine_t = afl_engine;
// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_shmem {
    pub shm_str: [libc::c_char; 20],
    pub shm_id: libc::c_int,
    pub map: *mut u8_0,
    pub map_size: size_t,
}
pub type afl_shmem_t = afl_shmem;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer {
    pub tag: u32_0,
    pub funcs: afl_observer_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer_funcs {
    pub flush: Option<unsafe extern "C" fn(_: *mut afl_observer_t) -> ()>,
    pub reset: Option<unsafe extern "C" fn(_: *mut afl_observer_t) -> ()>,
    pub post_exec: Option<unsafe extern "C" fn(_: *mut afl_observer_t,
                                               _: *mut afl_engine_t) -> ()>,
}
pub type afl_observer_t = afl_observer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer_covmap {
    pub base: afl_observer_t,
    pub shared_map: afl_shmem_t,
    pub funcs: afl_observer_covmap_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_observer_covmap_funcs {
    pub get_trace_bits: Option<unsafe extern "C" fn(_:
                                                        *mut afl_observer_covmap_t)
                                   -> *mut u8_0>,
    pub get_map_size: Option<unsafe extern "C" fn(_:
                                                      *mut afl_observer_covmap_t)
                                 -> size_t>,
}
pub type afl_observer_covmap_t = afl_observer_covmap;
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
pub unsafe extern "C" fn afl_observer_init(mut channel: *mut afl_observer_t)
 -> afl_ret_t {
    (*channel).tag = 0xb5eb45e as libc::c_int as u32_0;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_deinit(mut channel:
                                                 *mut afl_observer_t) {
    (*channel).tag = 0xaf1da10c as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_flush(mut channel:
                                                *mut afl_observer_t) {
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_reset(mut channel:
                                                *mut afl_observer_t) {
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_post_exec(mut channel:
                                                    *mut afl_observer_t) {
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_covmap_init(mut map_channel:
                                                      *mut afl_observer_covmap_t,
                                                  mut map_size: size_t)
 -> afl_ret_t {
    afl_observer_init(&mut (*map_channel).base);
    (*map_channel).base.tag = 0xb5ec0fe as libc::c_int as u32_0;
    if afl_shmem_init(&mut (*map_channel).shared_map, map_size).is_null() {
        return AFL_RET_ERROR_INITIALIZE
    }
    (*map_channel).base.funcs.reset =
        Some(afl_observer_covmap_reset as
                 unsafe extern "C" fn(_: *mut afl_observer_t) -> ());
    (*map_channel).funcs.get_map_size =
        Some(afl_observer_covmap_get_map_size as
                 unsafe extern "C" fn(_: *mut afl_observer_covmap_t)
                     -> size_t);
    (*map_channel).funcs.get_trace_bits =
        Some(afl_observer_covmap_get_trace_bits as
                 unsafe extern "C" fn(_: *mut afl_observer_covmap_t)
                     -> *mut u8_0);
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_covmap_deinit(mut map_channel:
                                                        *mut afl_observer_covmap_t) {
    afl_shmem_deinit(&mut (*map_channel).shared_map);
    afl_observer_deinit(&mut (*map_channel).base);
}
// Functions to initialize and delete a map based observation channel
#[no_mangle]
pub unsafe extern "C" fn afl_observer_covmap_reset(mut channel:
                                                       *mut afl_observer_t) {
    let mut map_channel: *mut afl_observer_covmap_t =
        channel as *mut afl_observer_covmap_t;
    memset((*map_channel).shared_map.map as *mut libc::c_void,
           0 as libc::c_int, (*map_channel).shared_map.map_size);
}
#[no_mangle]
pub unsafe extern "C" fn afl_observer_covmap_get_trace_bits(mut obs_channel:
                                                                *mut afl_observer_covmap_t)
 -> *mut u8_0 {
    return (*obs_channel).shared_map.map;
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
// vtable for the observation channel
/* They're void now, but I think post_exec should have some return type? Since,
 * they'll mostly be implemented by user */
// Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.
/* Function to create and destroy a new observation channel, allocates memory
  and initializes it. In destroy, it first deinitializes the struct and then
  frees it. */
// Base observation channel "class"
#[no_mangle]
pub unsafe extern "C" fn afl_observer_covmap_get_map_size(mut obs_channel:
                                                              *mut afl_observer_covmap_t)
 -> size_t {
    return (*obs_channel).shared_map.map_size;
}
