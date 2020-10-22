use ::libc;
extern "C" {
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    #[no_mangle]
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    #[no_mangle]
    fn fork() -> __pid_t;
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
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    #[no_mangle]
    fn pthread_create(__newthread: *mut pthread_t,
                      __attr: *const pthread_attr_t,
                      __start_routine:
                          Option<unsafe extern "C" fn(_: *mut libc::c_void)
                                     -> *mut libc::c_void>,
                      __arg: *mut libc::c_void) -> libc::c_int;
    #[no_mangle]
    fn connect(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t)
     -> libc::c_int;
    #[no_mangle]
    fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t)
     -> libc::c_int;
    #[no_mangle]
    fn socket(__domain: libc::c_int, __type: libc::c_int,
              __protocol: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn accept(__fd: libc::c_int, __addr: *mut sockaddr,
              __addr_len: *mut socklen_t) -> libc::c_int;
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
    #[no_mangle]
    fn htons(__hostshort: uint16_t) -> uint16_t;
    #[no_mangle]
    fn inet_addr(__cp: *const libc::c_char) -> in_addr_t;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn afl_shmem_deinit(sharedmem: *mut afl_shmem_t);
    #[no_mangle]
    fn afl_shmem_by_str(shm: *mut afl_shmem_t, shm_str: *mut libc::c_char,
                        map_size: size_t) -> *mut u8_0;
    #[no_mangle]
    fn afl_shmem_init(sharedmem: *mut afl_shmem_t, map_size: size_t)
     -> *mut u8_0;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __useconds_t = libc::c_uint;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub __pad1: *mut libc::c_void,
    pub __pad2: *mut libc::c_void,
    pub __pad3: *mut libc::c_void,
    pub __pad4: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_marker {
    pub _next: *mut _IO_marker,
    pub _sbuf: *mut _IO_FILE,
    pub _pos: libc::c_int,
}
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
pub type socklen_t = __socklen_t;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type pthread_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_attr_t {
    pub __size: [libc::c_char; 56],
    pub __align: libc::c_long,
}
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
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
/* This file includes return codes for libafl. */
/* Shorthand to check for RET_SUCCESS */
/* If expr != AFL_RET_SUCCESS, run block, error is in err. Return from here will return the parent func */
/* Shorthand to check for RET_SUCCESS and assign to ret */
pub type afl_ret_t = afl_ret;
pub type u8_0 = uint8_t;
pub type u16_0 = uint16_t;
pub type u32_0 = uint32_t;
pub type u64_0 = libc::c_ulonglong;
pub type s32 = int32_t;
pub type s64 = int64_t;
/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_alloc_buf {
    pub complete_size: size_t,
    pub magic: size_t,
    pub buf: [u8_0; 0],
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



 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_fuzz_one {
    pub engine: *mut afl_engine_t,
    pub stages: *mut *mut afl_stage_t,
    pub stages_count: size_t,
    pub funcs: afl_fuzz_one_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_fuzz_one_funcs {
    pub perform: Option<unsafe extern "C" fn(_: *mut afl_fuzz_one_t)
                            -> afl_ret_t>,
    pub add_stage: Option<unsafe extern "C" fn(_: *mut afl_fuzz_one_t,
                                               _: *mut afl_stage_t)
                              -> afl_ret_t>,
    pub set_engine: Option<unsafe extern "C" fn(_: *mut afl_fuzz_one_t,
                                                _: *mut afl_engine_t)
                               -> afl_ret_t>,
}
pub type afl_engine_t = afl_engine;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_engine {
    pub fuzz_one: *mut afl_fuzz_one_t,
    pub global_queue: *mut afl_queue_global_t,
    pub executor: *mut afl_executor_t,
    pub current_feedback_queue: *mut afl_queue_feedback_t,
    pub feedbacks: *mut *mut afl_feedback_t,
    pub executions: u64_0,
    pub start_time: u64_0,
    pub last_update: u64_0,
    pub crashes: u64_0,
    pub feedbacks_count: u64_0,
    pub id: u32_0,
    pub verbose: u8_0,
    pub cpu_bound: s32,
    pub in_dir: *mut libc::c_char,
    pub rand: afl_rand_t,
    pub buf: *mut u8_0,
    pub funcs: afl_engine_func,
    pub llmp_client: *mut llmp_client_t,
}
pub type llmp_client_t = llmp_client;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_client {
    pub id: u32_0,
    pub last_msg_recvd: *mut llmp_message_t,
    pub current_broadcast_map: *mut afl_shmem_t,
    pub last_msg_sent: *mut llmp_message_t,
    pub out_map_count: size_t,
    pub out_maps: *mut afl_shmem_t,
    pub new_out_page_hook_count: size_t,
    pub new_out_page_hooks: *mut llmp_hookdata_t,
}
pub type llmp_hookdata_t = llmp_hookdata_generic;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_hookdata_generic {
    pub func: *mut libc::c_void,
    pub data: *mut libc::c_void,
}
pub type afl_shmem_t = afl_shmem;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_shmem {
    pub shm_str: [libc::c_char; 20],
    pub shm_id: libc::c_int,
    pub map: *mut u8_0,
    pub map_size: size_t,
}
pub type llmp_message_t = llmp_message;
/*
A PoC for low level message passing

To send new messages, the clients place a new message at the end of their
client_out_map. If the ringbuf is filled up, they start place a
LLMP_AGE_END_OF_PAGE_V1 msg and alloc a new shmap.
Once the broker mapped a page, it flags it save for unmapping.

[client0]        [client1]    ...    [clientN]
  |                  |                 /
[client0_out] [client1_out] ... [clientN_out]
  |                 /                /
  |________________/                /
  |________________________________/
 \|/
[broker]

After the broker received a new message for clientN, (clientN_out->current_id
!= last_message->message_id) the broker will copy the message content to its
own, centralized page.

The clients periodically check (current_broadcast_map->current_id !=
last_message->message_id) for new incoming messages. If the page is filled up,
the broker instead creates a new page and places a LLMP_TAG_END_OF_PAGE_V1
message in its queue. The LLMP_TAG_END_PAGE_V1 buf contains the new string to
access the shared map. The clients then switch over to read from that new
current map.

[broker]
  |
[current_broadcast_map]
  |
  |___________________________________
  |_________________                  \
  |                 \                  \
  |                  |                  |
 \|/                \|/                \|/
[client0]        [client1]    ...    [clientN]

In the future, if we need zero copy, the current_broadcast_map could instead
list the client_out_map ID an offset for each message. In that case, the clients
also need to create new shmaps once their bufs are filled up.


To use, you will have to create a broker using llmp_broker_new().
Then register some clientloops using llmp_broker_register_threaded_clientloop
(or launch them as seperate processes) and call llmp_broker_run();

*/
// for sharedmem
/* We'll start of with 256 megabyte per fuzzer */
/* What byte count llmp messages should be aligned to */
/* llmp tags */
/* Storage class for hooks used at various places in llmp. */
/* The actual message.
    Sender is the original client id.
    The buf can be cast to any content.
    Once committed, this should not be touched again. */
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_message {
    pub tag: u32_0,
    pub sender: u32_0,
    pub message_id: u32_0,
    pub buf_len: size_t,
    pub buf_len_padded: size_t,
    pub buf: [u8_0; 0],
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

   The Engine is the main and central part of the fuzzer. It contains the
   queues, feedbacks, executor and the fuzz_one (which in turn has stages)

 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_engine_func {
    pub get_queue: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                              -> *mut afl_queue_global_t>,
    pub get_fuzz_one: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                                 -> *mut afl_fuzz_one_t>,
    pub get_execs: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                              -> u64_0>,
    pub get_start_time: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                                   -> u64_0>,
    pub set_fuzz_one: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                  _: *mut afl_fuzz_one_t)
                                 -> ()>,
    pub add_feedback: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                  _: *mut afl_feedback_t)
                                 -> afl_ret_t>,
    pub set_global_queue: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                      _:
                                                          *mut afl_queue_global_t)
                                     -> ()>,
    pub execute: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                             _: *mut afl_input_t) -> u8_0>,
    pub handle_new_message: Option<unsafe extern "C" fn(_: *mut afl_engine_t,
                                                        _:
                                                            *mut llmp_message_t)
                                       -> afl_ret_t>,
    pub load_testcases_from_dir: Option<unsafe extern "C" fn(_:
                                                                 *mut afl_engine_t,
                                                             _:
                                                                 *mut libc::c_char)
                                            -> afl_ret_t>,
    pub load_zero_testcase: Option<unsafe extern "C" fn(_: size_t) -> ()>,
    pub loop_0: Option<unsafe extern "C" fn(_: *mut afl_engine_t)
                           -> afl_ret_t>,
}
pub type afl_input_t = afl_input;
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
pub type afl_queue_global_t = afl_queue_global;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_global {
    pub base: afl_queue_t,
    pub feedback_queues: *mut *mut afl_queue_feedback_t,
    pub feedback_queues_count: size_t,
    pub funcs: afl_queue_global_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_global_funcs {
    pub schedule: Option<unsafe extern "C" fn(_: *mut afl_queue_global_t)
                             -> libc::c_int>,
    pub add_feedback_queue: Option<unsafe extern "C" fn(_:
                                                            *mut afl_queue_global_t,
                                                        _:
                                                            *mut afl_queue_feedback_t)
                                       -> afl_ret_t>,
}
// Inheritence from base queue
pub type afl_queue_feedback_t = afl_queue_feedback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_feedback {
    pub base: afl_queue_t,
    pub feedback: *mut afl_feedback_t,
    pub name: *mut libc::c_char,
}
pub type afl_feedback_t = afl_feedback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback {
    pub queue: *mut afl_queue_feedback_t,
    pub funcs: afl_feedback_funcs,
    pub tag: u32_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback_funcs {
    pub is_interesting: Option<unsafe extern "C" fn(_: *mut afl_feedback_t,
                                                    _: *mut afl_executor_t)
                                   -> libc::c_float>,
    pub set_feedback_queue: Option<unsafe extern "C" fn(_:
                                                            *mut afl_feedback_t,
                                                        _:
                                                            *mut afl_queue_feedback_t)
                                       -> ()>,
    pub get_feedback_queue: Option<unsafe extern "C" fn(_:
                                                            *mut afl_feedback_t)
                                       -> *mut afl_queue_feedback_t>,
}
pub type afl_executor_t = afl_executor;
// Reset the observation channels
// This is like the generic vtable for the executor.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_executor {
    pub observors: *mut *mut afl_observer_t,
    pub observors_count: u32_0,
    pub current_input: *mut afl_input_t,
    pub funcs: afl_executor_funcs,
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
/*
This is the generic forkserver interface that we have, in order to use the
library to build something, agin "inherit" from this struct (yes, we'll be
trying OO design principles here :D) and then extend adding your own fields to
it. See the example forksever executor that we have in examples/
*/
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_executor_funcs {
    pub init_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                            -> afl_ret_t>,
    pub destroy_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                               -> u8_0>,
    pub run_target_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                                  -> afl_exit_t>,
    pub place_input_cb: Option<unsafe extern "C" fn(_: *mut afl_executor_t,
                                                    _: *mut afl_input_t)
                                   -> u8_0>,
    pub observer_add: Option<unsafe extern "C" fn(_: *mut afl_executor_t,
                                                  _: *mut afl_observer_t)
                                 -> afl_ret_t>,
    pub input_get: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                              -> *mut afl_input_t>,
    pub observers_reset: Option<unsafe extern "C" fn(_: *mut afl_executor_t)
                                    -> ()>,
}
pub type afl_observer_t = afl_observer;
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
pub type afl_exit_t = afl_exit;
// This has a few parts, the first deals with crash handling.
/* afl_exit_t is for the fuzzed target, as opposed to afl_ret_t
which is for internal functions. */
pub type afl_exit = libc::c_uint;
pub const AFL_EXIT_OOM: afl_exit = 9;
pub const AFL_EXIT_TIMEOUT: afl_exit = 8;
pub const AFL_EXIT_FPE: afl_exit = 7;
pub const AFL_EXIT_ILL: afl_exit = 6;
pub const AFL_EXIT_ABRT: afl_exit = 5;
pub const AFL_EXIT_BUS: afl_exit = 4;
pub const AFL_EXIT_SEGV: afl_exit = 3;
pub const AFL_EXIT_CRASH: afl_exit = 2;
pub const AFL_EXIT_STOP: afl_exit = 1;
pub const AFL_EXIT_OK: afl_exit = 0;
pub type afl_queue_t = afl_queue;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue {
    pub entries: *mut *mut afl_entry_t,
    pub entries_count: size_t,
    pub base: *mut afl_entry_t,
    pub current: u64_0,
    pub engine_id: libc::c_int,
    pub engine: *mut afl_engine_t,
    pub end: *mut afl_entry_t,
    pub dirpath: [libc::c_char; 4096],
    pub names_id: size_t,
    pub save_to_files: bool,
    pub fuzz_started: bool,
    pub funcs: afl_queue_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_queue_funcs {
    pub insert: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                            _: *mut afl_entry_t)
                           -> afl_ret_t>,
    pub remove_from_queue: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                      -> ()>,
    pub get: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                        -> *mut afl_entry_t>,
    pub get_next_in_queue: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                       _: libc::c_int)
                                      -> *mut afl_entry_t>,
    pub get_queue_entry: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                     _: u32_0)
                                    -> *mut afl_entry_t>,
    pub get_queue_base: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                   -> *mut afl_entry_t>,
    pub get_size: Option<unsafe extern "C" fn(_: *mut afl_queue_t) -> size_t>,
    pub get_dirpath: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                -> *mut libc::c_char>,
    pub get_names_id: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                 -> size_t>,
    pub get_save_to_files: Option<unsafe extern "C" fn(_: *mut afl_queue_t)
                                      -> bool>,
    pub set_dirpath: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                 _: *mut libc::c_char) -> ()>,
    pub set_engine: Option<unsafe extern "C" fn(_: *mut afl_queue_t,
                                                _: *mut afl_engine_t) -> ()>,
}
pub type afl_entry_t = afl_entry;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_entry {
    pub info: *mut afl_entry_info_t,
    pub input: *mut afl_input_t,
    pub map: *mut u8_0,
    pub on_disk: bool,
    pub info_calloc: bool,
    pub filename: [libc::c_char; 4120],
    pub queue: *mut afl_queue,
    pub next: *mut afl_entry,
    pub prev: *mut afl_entry,
    pub parent: *mut afl_entry,
    pub funcs: afl_entry_funcs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_entry_funcs {
    pub get_input: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                              -> *mut afl_input_t>,
    pub is_on_disk: Option<unsafe extern "C" fn(_: *mut afl_entry_t) -> bool>,
    pub get_next: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                             -> *mut afl_entry_t>,
    pub get_prev: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                             -> *mut afl_entry_t>,
    pub get_parent: Option<unsafe extern "C" fn(_: *mut afl_entry_t)
                               -> *mut afl_entry_t>,
    pub get_child: Option<unsafe extern "C" fn(_: *mut afl_entry_t, _: size_t)
                              -> *mut afl_entry_t>,
}
pub type afl_entry_info_t = afl_entry_info;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct afl_entry_info {
    pub hash: u64_0,
    pub exec_us: u64_0,
    pub bytes_set: u32_0,
    pub bits_set: u32_0,
    pub trimmed: u8_0,
    pub has_new_coverage: u8_0,
    pub variable: u8_0,
    pub skip_entry: u8_0,
}
pub type afl_fuzz_one_t = afl_fuzz_one;
pub type afl_rand_t = afl_rand;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_rand {
    pub rand_cnt: u32_0,
    pub rand_seed: [u64_0; 4],
    pub dev_urandom_fd: s32,
    pub init_seed: s64,
    pub fixed_seed: bool,
}
pub type afl_stage_t = afl_stage;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_stage {
    pub engine: *mut afl_engine_t,
    pub funcs: afl_stage_funcs,
    pub mutators: *mut *mut afl_mutator_t,
    pub mutators_count: size_t,
}
pub type afl_mutator_t = afl_mutator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator {
    pub engine: *mut afl_engine_t,
    pub mutate_buf: *mut u8_0,
    pub funcs: afl_mutator_funcs,
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


 */
// Mutator struct will have many internal functions like mutate, trimming etc.
// This is based on both the FFF prototype and the custom mutators that we have
// in AFL++ without the AFL++ specific parts
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator_funcs {
    pub init: Option<unsafe extern "C" fn(_: *mut afl_mutator_t) -> ()>,
    pub trim: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                          _: *mut afl_input_t) -> size_t>,
    pub mutate: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                            _: *mut afl_input_t) -> size_t>,
    pub custom_queue_get: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                                      _: *mut afl_input_t)
                                     -> afl_ret_t>,
    pub custom_queue_new_entry: Option<unsafe extern "C" fn(_:
                                                                *mut afl_mutator_t,
                                                            _:
                                                                *mut afl_entry_t)
                                           -> ()>,
    pub post_process: Option<unsafe extern "C" fn(_: *mut afl_mutator_t,
                                                  _: *mut afl_input_t) -> ()>,
    pub get_stage: Option<unsafe extern "C" fn(_: *mut afl_mutator_t)
                              -> *mut afl_stage_t>,
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

 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_stage_funcs {
    pub perform: Option<unsafe extern "C" fn(_: *mut afl_stage_t,
                                             _: *mut afl_input_t)
                            -> afl_ret_t>,
    pub get_iters: Option<unsafe extern "C" fn(_: *mut afl_stage_t)
                              -> size_t>,
    pub add_mutator_to_stage: Option<unsafe extern "C" fn(_: *mut afl_stage_t,
                                                          _:
                                                              *mut afl_mutator_t)
                                         -> afl_ret_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_broker_state {
    pub last_msg_sent: *mut llmp_message_t,
    pub broadcast_map_count: size_t,
    pub broadcast_maps: *mut afl_shmem_t,
    pub msg_hook_count: size_t,
    pub msg_hooks: *mut llmp_hookdata_t,
    pub llmp_client_count: size_t,
    pub llmp_clients: *mut llmp_broker_clientdata_t,
}
pub type llmp_broker_clientdata_t = llmp_broker_client_metadata;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_broker_client_metadata {
    pub client_type: LLMP_CLIENT_TYPE,
    pub client_state: *mut llmp_client_t,
    pub cur_client_map: *mut afl_shmem_t,
    pub last_msg_broker_read: *mut llmp_message_t,
    pub pthread: *mut pthread_t,
    pub pid: libc::c_int,
    pub clientloop: llmp_clientloop_func,
    pub engine: *mut afl_engine_t,
    pub data: *mut libc::c_void,
}
pub type llmp_clientloop_func
    =
    Option<unsafe extern "C" fn(_: *mut llmp_client_t, _: *mut libc::c_void)
               -> ()>;
pub type LLMP_CLIENT_TYPE = libc::c_uint;
pub const LLMP_CLIENT_TYPE_FOREIGN_PROCESS: LLMP_CLIENT_TYPE = 3;
pub const LLMP_CLIENT_TYPE_CHILD_PROCESS: LLMP_CLIENT_TYPE = 2;
pub const LLMP_CLIENT_TYPE_PTHREAD: LLMP_CLIENT_TYPE = 1;
pub const LLMP_CLIENT_TYPE_UNKNOWN: LLMP_CLIENT_TYPE = 0;
pub type llmp_broker_t = llmp_broker_state;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_page {
    pub sender: u32_0,
    pub save_to_unmap: u16_0,
    pub sender_dead: u16_0,
    pub current_msg_id: size_t,
    pub size_total: size_t,
    pub size_used: size_t,
    pub max_alloc_size: size_t,
    pub messages: [llmp_message_t; 0],
}
pub type llmp_page_t = llmp_page;
pub type llmp_message_hook_func
    =
    unsafe extern "C" fn(_: *mut llmp_broker_t,
                         _: *mut llmp_broker_clientdata_t,
                         _: *mut llmp_message_t, _: *mut libc::c_void)
        -> bool;
pub type llmp_client_new_page_hook_func
    =
    unsafe extern "C" fn(_: *mut llmp_client_t, _: *mut llmp_page_t,
                         _: *mut libc::c_void) -> ();
/* Just a random msg */
/* Message payload when a client got added LLMP_TAG_CLIENT_ADDED_V1 */
/* A new sharedmap appeared.
  This is an internal message!
  LLMP_TAG_NEW_PAGE_V1
  */
pub type llmp_payload_new_page_t = llmp_payload_new_page;
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_payload_new_page {
    pub map_size: size_t,
    pub shm_str: [libc::c_char; 20],
}
/* size of this map */
/* 0-terminated str handle for this map */
/* Returns a string representation of afl_ret_t or of the errno if applicable */
#[inline]
unsafe extern "C" fn afl_ret_stringify(mut afl_ret: afl_ret_t)
 -> *mut libc::c_char {
    let mut current_block_17: u64;
    match afl_ret as libc::c_uint {
        0 => {
            return b"Success\x00" as *const u8 as *const libc::c_char as
                       *mut libc::c_char
        }
        8 => {
            return b"No more elements in array\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        9 => {
            return b"Could not execute target\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        10 => {
            return b"Target did not behave as expected\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        19 => {
            return b"Error creating input copy\x00" as *const u8 as
                       *const libc::c_char as *mut libc::c_char
        }
        20 => {
            return b"Empty data\x00" as *const u8 as *const libc::c_char as
                       *mut libc::c_char
        }
        2 => {
            return b"File exists\x00" as *const u8 as *const libc::c_char as
                       *mut libc::c_char
        }
        3 => {
            if *__errno_location() == 0 {
                return b"Allocation failed\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 15859320420022735487;
        }
        4 => { current_block_17 = 15859320420022735487; }
        6 => { current_block_17 = 8169317795695357680; }
        12 => { current_block_17 = 10284973786955371720; }
        _ => {
            return b"Unknown error. Please report this bug!\x00" as *const u8
                       as *const libc::c_char as *mut libc::c_char
        }
    }
    match current_block_17 {
        15859320420022735487 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Error opening file\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 8169317795695357680;
        }
        _ => { }
    }
    match current_block_17 {
        8169317795695357680 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Got less bytes than expected\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
        }
        _ => { }
    }
    /* fall-through */
    return strerror(*__errno_location());
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
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Illegal, non-null pointer passed to afl_realloc (buf 0x%p, magic 0x%x)\x00"
                       as *const u8 as *const libc::c_char, new_buf,
                   (*new_buf).magic as libc::c_uint);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
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
#[inline]
unsafe extern "C" fn shmem2page(mut afl_shmem: *mut afl_shmem_t)
 -> *mut llmp_page_t {
    return (*afl_shmem).map as *mut llmp_page_t;
}
/* If a msg is contained in the current page */
#[no_mangle]
pub unsafe extern "C" fn llmp_msg_in_page(mut page: *mut llmp_page_t,
                                          mut msg: *mut llmp_message_t)
 -> bool {
    /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total); */
    return (page as *mut u8_0) < msg as *mut u8_0 &&
               (page as *mut u8_0).offset((*page).size_total as isize) >
                   msg as *mut u8_0;
}
/* allign to LLMP_ALIGNNMENT bytes */
#[inline]
unsafe extern "C" fn llmp_align(mut to_align: size_t) -> size_t {
    if 64 as libc::c_int == 0 as libc::c_int ||
           to_align.wrapping_rem(64 as libc::c_int as libc::c_ulong) ==
               0 as libc::c_int as libc::c_ulong {
        return to_align
    }
    return to_align.wrapping_add((64 as libc::c_int as
                                      libc::c_ulong).wrapping_sub(to_align.wrapping_rem(64
                                                                                            as
                                                                                            libc::c_int
                                                                                            as
                                                                                            libc::c_ulong)));
}
/* In case we don't have enough space, make sure the next page will be large
  enough. For now, we want to have at least enough space to store 2 of the
  largest messages we encountered. */
#[inline]
unsafe extern "C" fn new_map_size(mut max_alloc: size_t) -> size_t {
    return next_pow2(({
                          let mut _a: libc::c_ulong =
                              max_alloc.wrapping_mul(2 as libc::c_int as
                                                         libc::c_ulong).wrapping_add(llmp_align((::std::mem::size_of::<llmp_message_t>()
                                                                                                     as
                                                                                                     libc::c_ulong).wrapping_add(::std::mem::size_of::<llmp_payload_new_page_t>()
                                                                                                                                     as
                                                                                                                                     libc::c_ulong)));
                          let mut _b: size_t =
                              ((1 as libc::c_int) << 28 as libc::c_int) as
                                  size_t;
                          if _a > _b { _a } else { _b }
                      }));
}
/* Initialize a new llmp_page_t. size should be relative to
 * llmp_page_t->messages */
unsafe extern "C" fn _llmp_page_init(mut page: *mut llmp_page_t,
                                     mut sender: u32_0, mut size: size_t) {
    printf(b"[D] [src/llmp.c:155] _llmp_page_init %p %u %lu\n\x00" as
               *const u8 as *const libc::c_char, page, sender, size);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    (*page).sender = sender;
    ::std::ptr::write_volatile(&mut (*page).current_msg_id as *mut size_t,
                               0 as libc::c_int as size_t);
    (*page).max_alloc_size = 0 as libc::c_int as size_t;
    (*page).size_total = size;
    (*page).size_used = 0 as libc::c_int as size_t;
    (*(*page).messages.as_mut_ptr()).message_id = 0 as libc::c_int as u32_0;
    (*(*page).messages.as_mut_ptr()).tag =
        0xdeadaf as libc::c_longlong as u32_0;
    ::std::ptr::write_volatile(&mut (*page).save_to_unmap as *mut u16_0,
                               0 as libc::c_int as u16_0);
    ::std::ptr::write_volatile(&mut (*page).sender_dead as *mut u16_0,
                               0 as libc::c_int as u16_0);
}
/* Pointer to the message behind the last message */
#[inline]
unsafe extern "C" fn _llmp_next_msg_ptr(mut last_msg: *mut llmp_message_t)
 -> *mut llmp_message_t {
    /* DBG("_llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len_padded, sizeof(llmp_message_t)); */
    return (last_msg as
                *mut u8_0).offset(::std::mem::size_of::<llmp_message_t>() as
                                      libc::c_ulong as
                                      isize).offset((*last_msg).buf_len_padded
                                                        as isize) as
               *mut llmp_message_t;
}
/* Read next message. */
#[no_mangle]
pub unsafe extern "C" fn llmp_recv(mut page: *mut llmp_page_t,
                                   mut last_msg: *mut llmp_message_t)
 -> *mut llmp_message_t {
    /* DBG("llmp_recv %p %p\n", page, last_msg); */
    asm!("" : : : "memory" : "volatile");
    if (*page).current_msg_id == 0 {
        /* No messages yet */
        return 0 as *mut llmp_message_t
    } else if last_msg.is_null() {
        /* We never read a message from this queue. Return first. */
        return (*page).messages.as_mut_ptr()
    } else if (*last_msg).message_id as libc::c_ulong ==
                  (*page).current_msg_id {
        /* Oops! No new message! */
        return 0 as *mut llmp_message_t
    } else { return _llmp_next_msg_ptr(last_msg) };
}
/* Blocks/spins until the next message gets posted to the page,
  then returns that message. */
#[no_mangle]
pub unsafe extern "C" fn llmp_recv_blocking(mut page: *mut llmp_page_t,
                                            mut last_msg: *mut llmp_message_t)
 -> *mut llmp_message_t {
    printf(b"[D] [src/llmp.c:211] llmp_recv_blocking %p %p page->current_msg_id %lu last_msg->message_id %u\n\x00"
               as *const u8 as *const libc::c_char, page, last_msg,
           (*page).current_msg_id, (*last_msg).message_id);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut current_msg_id: u32_0 = 0 as libc::c_int as u32_0;
    if !last_msg.is_null() {
        if (*last_msg).tag == 0xaf1e0f1 as libc::c_int as libc::c_uint &&
               llmp_msg_in_page(page, last_msg) as libc::c_int != 0 {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: full page passed to await_message_blocking or reset failed\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 19],
                                             &[libc::c_char; 19]>(b"llmp_recv_blocking\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   218 as libc::c_int);
            exit(1 as libc::c_int);
        }
        current_msg_id = (*last_msg).message_id
    }
    loop  {
        asm!("" : : : "memory" : "volatile");
        if (*page).current_msg_id != current_msg_id as libc::c_ulong {
            let mut ret: *mut llmp_message_t = llmp_recv(page, last_msg);
            if ret.is_null() {
                printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: blocking llmp message should never be NULL!\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                           *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 19],
                                                 &[libc::c_char; 19]>(b"llmp_recv_blocking\x00")).as_ptr(),
                       b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                       232 as libc::c_int);
                exit(1 as libc::c_int);
            }
            return ret
        }
    };
}
/* Special allocation function for EOP messages (and nothing else!)
  The normal alloc will fail if there is not enough space for buf_len_padded + EOP
  So if llmp_alloc_next fails, create new page if necessary, use this function,
  place EOP, commit EOP, reset, alloc again on the new space.
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_alloc_eop(mut page: *mut llmp_page_t,
                                        mut last_msg: *mut llmp_message_t)
 -> *mut llmp_message_t {
    if !llmp_msg_in_page(page, last_msg) {
        /* This should only happen if the initial alloc > initial page len */
        printf(b"[D] [src/llmp.c:254] EOP without any useful last_msg in the current page. size_used %ld, size_total %ld, last_msg_ptr: %p, max_alloc_size: %ld\x00"
                   as *const u8 as *const libc::c_char, (*page).size_used,
               (*page).size_total, last_msg, (*page).max_alloc_size);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
    }
    if (*page).size_used.wrapping_add(llmp_align((::std::mem::size_of::<llmp_message_t>()
                                                      as
                                                      libc::c_ulong).wrapping_add(::std::mem::size_of::<llmp_payload_new_page_t>()
                                                                                      as
                                                                                      libc::c_ulong)))
           > (*page).size_total {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: EOP does not fit in page! page %p, size_current %zu, size_total %zu\x00"
                   as *const u8 as *const libc::c_char, page,
               (*page).size_used, (*page).size_total);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 15],
                                         &[libc::c_char; 15]>(b"llmp_alloc_eop\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               265 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut ret: *mut llmp_message_t =
        if !last_msg.is_null() {
            _llmp_next_msg_ptr(last_msg)
        } else { (*page).messages.as_mut_ptr() };
    if (*ret).tag == 0xa143af11 as libc::c_uint {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Did not call send() on last message!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 15],
                                         &[libc::c_char; 15]>(b"llmp_alloc_eop\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               271 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*ret).buf_len_padded =
        ::std::mem::size_of::<llmp_payload_new_page_t>() as libc::c_ulong;
    (*ret).message_id =
        if !last_msg.is_null() {
            (*last_msg).message_id =
                ((*last_msg).message_id as
                     libc::c_uint).wrapping_add(1 as libc::c_int as
                                                    libc::c_uint) as u32_0 as
                    u32_0;
            (*last_msg).message_id
        } else { 1 as libc::c_int as libc::c_uint };
    (*ret).tag = 0xaf1e0f1 as libc::c_int as u32_0;
    (*page).size_used =
        ((*page).size_used as
             libc::c_ulong).wrapping_add(llmp_align((::std::mem::size_of::<llmp_message_t>()
                                                         as
                                                         libc::c_ulong).wrapping_add(::std::mem::size_of::<llmp_payload_new_page_t>()
                                                                                         as
                                                                                         libc::c_ulong)))
            as size_t as size_t;
    return ret;
}
/* Will return a ptr to the next msg buf, or NULL if map is full.
Never call alloc_next without either sending or cancelling the last allocated message for this page!
There can only ever be up to one message allocated per page at each given time.
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_alloc_next(mut page: *mut llmp_page_t,
                                         mut last_msg: *mut llmp_message_t,
                                         mut buf_len: size_t)
 -> *mut llmp_message_t {
    printf(b"[D] [src/llmp.c:289] llmp_alloc_next %p %p %lu\n\x00" as
               *const u8 as *const libc::c_char, page, last_msg, buf_len);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut buf_len_padded: size_t = buf_len;
    let mut complete_msg_size: size_t =
        llmp_align((::std::mem::size_of::<llmp_message_t>() as
                        libc::c_ulong).wrapping_add(buf_len_padded));
    /* DBG("XXX complete_msg_size %lu (h: %lu)\n", complete_msg_size, sizeof(llmp_message_t)); */
    /* In case we don't have enough space, make sure the next page will be large
   * enough */
    (*page).max_alloc_size =
        ({
             let mut _a: size_t = (*page).max_alloc_size;
             let mut _b: size_t = complete_msg_size;
             if _a > _b { _a } else { _b }
         });
    let mut ret: *mut llmp_message_t = 0 as *mut llmp_message_t;
    /* DBG("last_msg %p %d (%d)\n", last_msg, last_msg ? (int)last_msg->tag : -1, (int)LLMP_TAG_END_OF_PAGE_V1); */
    if last_msg.is_null() ||
           (*last_msg).tag == 0xaf1e0f1 as libc::c_int as libc::c_uint {
        /* We start fresh */
        ret = (*page).messages.as_mut_ptr();
        /* The initial message may not be alligned, so we at least align the end of
    it. Technically, size_t can be smaller than a pointer, then who knows what
    happens */
        let mut base_addr: size_t = ret as size_t;
        buf_len_padded =
            llmp_align(base_addr.wrapping_add(complete_msg_size)).wrapping_sub(base_addr).wrapping_sub(::std::mem::size_of::<llmp_message_t>()
                                                                                                           as
                                                                                                           libc::c_ulong);
        complete_msg_size =
            buf_len_padded.wrapping_add(::std::mem::size_of::<llmp_message_t>()
                                            as libc::c_ulong);
        /* DBG("XXX complete_msg_size NEW %lu\n", complete_msg_size); */
        /* Still space for the new message plus the additional "we're full" message?
     */
        if (*page).size_used.wrapping_add(complete_msg_size).wrapping_add(llmp_align((::std::mem::size_of::<llmp_message_t>()
                                                                                          as
                                                                                          libc::c_ulong).wrapping_add(::std::mem::size_of::<llmp_payload_new_page_t>()
                                                                                                                          as
                                                                                                                          libc::c_ulong)))
               > (*page).size_total {
            printf(b"[D] [src/llmp.c:322] No more space in page (tried %ld bytes + END_OF_PAGE_LEN, used: %ld, total size %ld). Returning NULL\x00"
                       as *const u8 as *const libc::c_char, buf_len_padded,
                   (*page).size_used, (*page).size_total);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            /* We're full. */
            return 0 as *mut llmp_message_t
        }
        /* We need to start with 1 for ids, as current message id is initialized
     * with 0... */
        (*ret).message_id =
            if !last_msg.is_null() {
                (*last_msg).message_id.wrapping_add(1 as libc::c_int as
                                                        libc::c_uint)
            } else { 1 as libc::c_int as libc::c_uint }
    } else if (*page).current_msg_id !=
                  (*last_msg).message_id as libc::c_ulong {
        /* Oops, wrong usage! */
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: The current message never got commited using llmp_send! (page->current_msg_id %zu, last_msg->message_id: %d)\x00"
                   as *const u8 as *const libc::c_char,
               (*page).current_msg_id, (*last_msg).message_id);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 16],
                                         &[libc::c_char; 16]>(b"llmp_alloc_next\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               339 as libc::c_int);
        exit(1 as libc::c_int);
    } else {
        buf_len_padded =
            complete_msg_size.wrapping_sub(::std::mem::size_of::<llmp_message_t>()
                                               as libc::c_ulong);
        /* DBG("XXX ret %p id %u buf_len_padded %lu complete_msg_size %lu\n", ret, ret->message_id, buf_len_padded,
     * complete_msg_size); */
        if (*page).size_used.wrapping_add(complete_msg_size).wrapping_add(llmp_align((::std::mem::size_of::<llmp_message_t>()
                                                                                          as
                                                                                          libc::c_ulong).wrapping_add(::std::mem::size_of::<llmp_payload_new_page_t>()
                                                                                                                          as
                                                                                                                          libc::c_ulong)))
               > (*page).size_total {
            printf(b"[D] [src/llmp.c:352] No more space in page (tried %ld bytes + END_OF_PAGE_LEN, used: %ld, total size %ld). Returning NULL\x00"
                       as *const u8 as *const libc::c_char, buf_len_padded,
                   (*page).size_used, (*page).size_total);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            /* Still space for the new message plus the additional "we're full" message?
     */
            /* We're full. */
            return 0 as *mut llmp_message_t
        }
        ret = _llmp_next_msg_ptr(last_msg);
        (*ret).message_id =
            (*last_msg).message_id.wrapping_add(1 as libc::c_int as
                                                    libc::c_uint)
    }
    /* The beginning of our message should be messages + size_used, else nobody
   * sent the last msg! */
    /* DBG("XXX ret %p - page->messages %p = %lu != %lu, will add %lu -> %p\n", ret, page->messages,
      (size_t)((u8 *)ret - (u8 *)page->messages), page->size_used, complete_msg_size, ((u8 *)ret) + complete_msg_size);
   */
    if last_msg.is_null() && (*page).size_used != 0 ||
           (ret as
                *mut u8_0).wrapping_offset_from((*page).messages.as_mut_ptr()
                                                    as *mut u8_0) as
               libc::c_long as size_t != (*page).size_used {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Allocated new message without calling send() inbetween. ret: %p, page: %p, complete_msg_size: %zu, size_used: %zu, last_msg: %p, page->messages %p\x00"
                   as *const u8 as *const libc::c_char, ret, page,
               buf_len_padded, (*page).size_used, last_msg,
               (*page).messages.as_mut_ptr());
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 16],
                                         &[libc::c_char; 16]>(b"llmp_alloc_next\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               378 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*page).size_used =
        ((*page).size_used as libc::c_ulong).wrapping_add(complete_msg_size)
            as size_t as size_t;
    (*ret).buf_len_padded = buf_len_padded;
    (*ret).buf_len = buf_len;
    /* DBG("Returning new message at %p with len %ld, TAG was %x", ret, ret->buf_len_padded, ret->tag); */
    /* Maybe catch some bugs... */
    (*_llmp_next_msg_ptr(ret)).tag = 0xdeadaf as libc::c_longlong as u32_0;
    (*ret).tag = 0xa143af11 as libc::c_uint;
    return ret;
}
/* Commit the message last allocated by llmp_alloc_next to the queue.
  After commiting, the msg shall no longer be altered!
  It will be read by the consuming threads (broker->clients or client->broker)
 */
#[no_mangle]
pub unsafe extern "C" fn llmp_send(mut page: *mut llmp_page_t,
                                   mut msg: *mut llmp_message_t) -> bool {
    printf(b"[D] [src/llmp.c:403] llmp_send %p %p message_id %u\n\x00" as
               *const u8 as *const libc::c_char, page, msg,
           (*msg).message_id);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    if (*msg).tag as libc::c_longlong == 0xdeadaf as libc::c_longlong {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : No tag set on message with id %d!\x00"
                   as *const u8 as *const libc::c_char, (*msg).message_id);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 10],
                                         &[libc::c_char; 10]>(b"llmp_send\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               405 as libc::c_int);
        exit(1 as libc::c_int);
    }
    if msg.is_null() || !llmp_msg_in_page(page, msg) {
        printf(b"[D] [src/llmp.c:409] BUG: Uh-Oh! Wrong msg passed to llmp_send_allocated :(\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    asm!("" : : : "memory" : "volatile");
    ::std::ptr::write_volatile(&mut (*page).current_msg_id as *mut size_t,
                               (*msg).message_id as size_t);
    asm!("" : : : "memory" : "volatile");
    return 1 as libc::c_int != 0;
}
#[inline]
unsafe extern "C" fn _llmp_broker_current_broadcast_map(mut broker_state:
                                                            *mut llmp_broker_t)
 -> *mut afl_shmem_t {
    printf(b"[D] [src/llmp.c:424] _llmp_broker_current_broadcast_map %p [%u]-> %p\n\x00"
               as *const u8 as *const libc::c_char, broker_state,
           ((*broker_state).broadcast_map_count as
                u32_0).wrapping_sub(1 as libc::c_int as libc::c_uint),
           &mut *(*broker_state).broadcast_maps.offset((*broker_state).broadcast_map_count.wrapping_sub(1
                                                                                                            as
                                                                                                            libc::c_int
                                                                                                            as
                                                                                                            libc::c_ulong)
                                                           as isize) as
               *mut afl_shmem_t);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    return &mut *(*broker_state).broadcast_maps.offset((*broker_state).broadcast_map_count.wrapping_sub(1
                                                                                                            as
                                                                                                            libc::c_int
                                                                                                            as
                                                                                                            libc::c_ulong)
                                                           as isize) as
               *mut afl_shmem_t;
}
/* create a new shard page. Size_requested will be the min size, you may get a
 * larger map. Retruns NULL on error. */
#[no_mangle]
pub unsafe extern "C" fn llmp_new_page_shmem(mut uninited_afl_shmem:
                                                 *mut afl_shmem_t,
                                             mut sender: size_t,
                                             mut size_requested: size_t)
 -> *mut llmp_page_t {
    let mut size: size_t =
        next_pow2(({
                       let mut _a: libc::c_ulong =
                           size_requested.wrapping_add(40 as libc::c_ulong);
                       let mut _b: size_t =
                           ((1 as libc::c_int) << 28 as libc::c_int) as
                               size_t;
                       if _a > _b { _a } else { _b }
                   }));
    if afl_shmem_init(uninited_afl_shmem, size).is_null() {
        return 0 as *mut llmp_page_t
    }
    _llmp_page_init(shmem2page(uninited_afl_shmem), sender as u32_0,
                    size_requested);
    printf(b"[D] [src/llmp.c:436] llmp_new_page_shmem %p %lu %lu -> size %lu\n\x00"
               as *const u8 as *const libc::c_char, uninited_afl_shmem,
           sender, size_requested, size);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    return shmem2page(uninited_afl_shmem);
}
/* This function handles EOP by creating a new shared page and informing the
  listener about it using a EOP message. */
unsafe extern "C" fn llmp_handle_out_eop(mut maps: *mut afl_shmem_t,
                                         mut map_count_p: *mut size_t,
                                         mut last_msg_p:
                                             *mut *mut llmp_message_t)
 -> *mut afl_shmem_t {
    printf(b"[D] [src/llmp.c:445] llmp_handle_out_eop %p %p=%lu %p=%p\n\x00"
               as *const u8 as *const libc::c_char, maps, map_count_p,
           *map_count_p, last_msg_p, *last_msg_p);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut map_count: u32_0 = *map_count_p as u32_0;
    let mut old_map: *mut llmp_page_t =
        shmem2page(&mut *maps.offset(map_count.wrapping_sub(1 as libc::c_int
                                                                as
                                                                libc::c_uint)
                                         as isize));
    maps =
        afl_realloc(maps as *mut libc::c_void,
                    (map_count.wrapping_add(1 as libc::c_int as libc::c_uint)
                         as
                         libc::c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem_t>()
                                                         as libc::c_ulong)) as
            *mut afl_shmem_t;
    if maps.is_null() {
        printf(b"[D] [src/llmp.c:452] Unable to alloc space for broker map\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as *mut afl_shmem_t
    }
    /* Broadcast a new, large enough, message. Also sorry for that c ptr stuff! */
    let mut new_map: *mut llmp_page_t =
        llmp_new_page_shmem(&mut *maps.offset(map_count as isize),
                            (*old_map).sender as size_t,
                            new_map_size((*old_map).max_alloc_size));
    if new_map.is_null() {
        printf(b"[D] [src/llmp.c:461] Unable to initialize new broker page\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_free(maps as *mut libc::c_void);
        return 0 as *mut afl_shmem_t
    }
    /* Realloc may have changed the location of maps_p (and old_map) in memory :/
   */
    old_map =
        shmem2page(&mut *maps.offset(map_count.wrapping_sub(1 as libc::c_int
                                                                as
                                                                libc::c_uint)
                                         as isize));
    *map_count_p =
        map_count.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t;
    ::std::ptr::write_volatile(&mut (*new_map).current_msg_id as *mut size_t,
                               (*old_map).current_msg_id);
    (*new_map).max_alloc_size = (*old_map).max_alloc_size;
    /* On the old map, place a last message linking to the new map for the clients
   * to consume */
    let mut out: *mut llmp_message_t = llmp_alloc_eop(old_map, *last_msg_p);
    (*out).sender = (*old_map).sender;
    let mut new_page_msg: *mut llmp_payload_new_page_t =
        (*out).buf.as_mut_ptr() as *mut llmp_payload_new_page_t;
    /* copy the infos to the message we're going to send on the old buf */
    (*new_page_msg).map_size = (*maps.offset(map_count as isize)).map_size;
    memcpy((*new_page_msg).shm_str.as_mut_ptr() as *mut libc::c_void,
           (*maps.offset(map_count as isize)).shm_str.as_mut_ptr() as
               *const libc::c_void, 20 as libc::c_int as libc::c_ulong);
    // We never sent a msg on the new buf */
    *last_msg_p = 0 as *mut llmp_message_t;
    /* Send the last msg on the old buf */
    if !llmp_send(old_map, out) {
        printf(b"[D] [src/llmp.c:494] Could not inform the broker!\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_free(maps as *mut libc::c_void);
        return 0 as *mut afl_shmem_t
    }
    return maps;
}
/* no more space left! We'll have to start a new page */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_handle_out_eop(mut broker:
                                                        *mut llmp_broker_t)
 -> afl_ret_t {
    printf(b"[D] [src/llmp.c:507] Broadcasting broker EOP\x00" as *const u8 as
               *const libc::c_char);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    (*broker).broadcast_maps =
        llmp_handle_out_eop((*broker).broadcast_maps,
                            &mut (*broker).broadcast_map_count,
                            &mut (*broker).last_msg_sent);
    return if !(*broker).broadcast_maps.is_null() {
               AFL_RET_SUCCESS as libc::c_int
           } else { AFL_RET_ALLOC as libc::c_int } as afl_ret_t;
}
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_alloc_next(mut broker:
                                                    *mut llmp_broker_t,
                                                mut len: size_t)
 -> *mut llmp_message_t {
    let mut broadcast_page: *mut llmp_page_t =
        shmem2page(_llmp_broker_current_broadcast_map(broker));
    let mut out: *mut llmp_message_t =
        llmp_alloc_next(broadcast_page, (*broker).last_msg_sent, len);
    if out.is_null() {
        /* no more space left! We'll have to start a new page */
        let mut ret: afl_ret_t = llmp_broker_handle_out_eop(broker);
        if ret as libc::c_uint !=
               AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : %s\x00" as *const u8 as
                       *const libc::c_char, afl_ret_stringify(ret));
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"llmp_broker_alloc_next\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   524 as libc::c_int);
            exit(1 as libc::c_int);
        }
        /* llmp_handle_out_eop allocates a new current broadcast_map */
        broadcast_page =
            shmem2page(_llmp_broker_current_broadcast_map(broker));
        /* the alloc is now on a new page */
        out = llmp_alloc_next(broadcast_page, (*broker).last_msg_sent, len);
        if out.is_null() {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error allocating %zu bytes in shmap %s\x00"
                       as *const u8 as *const libc::c_char, len,
                   (*_llmp_broker_current_broadcast_map(broker)).shm_str.as_mut_ptr());
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"llmp_broker_alloc_next\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   533 as libc::c_int);
            exit(1 as libc::c_int);
        }
    }
    return out;
}
/* Registers a new client for the given sharedmap str and size.
  Be careful: Intenral realloc may change the location of the client map */
unsafe extern "C" fn llmp_broker_register_client(mut broker:
                                                     *mut llmp_broker_t,
                                                 mut shm_str:
                                                     *mut libc::c_char,
                                                 mut map_size: size_t)
 -> *mut llmp_broker_clientdata_t {
    /* make space for a new client and calculate its id */
    (*broker).llmp_clients =
        afl_realloc((*broker).llmp_clients as *mut libc::c_void,
                    (*broker).llmp_client_count.wrapping_add(1 as libc::c_int
                                                                 as
                                                                 libc::c_ulong).wrapping_mul(::std::mem::size_of::<llmp_broker_clientdata_t>()
                                                                                                 as
                                                                                                 libc::c_ulong))
            as *mut llmp_broker_clientdata_t;
    if (*broker).llmp_clients.is_null() {
        printf(b"[D] [src/llmp.c:551] Failed to register new client!\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as *mut llmp_broker_clientdata_t
    }
    let mut client: *mut llmp_broker_clientdata_t =
        &mut *(*broker).llmp_clients.offset((*broker).llmp_client_count as
                                                isize) as
            *mut llmp_broker_clientdata_t;
    memset(client as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<llmp_broker_clientdata_t>() as
               libc::c_ulong);
    (*client).client_state =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<llmp_client_t>() as libc::c_ulong) as
            *mut llmp_client_t;
    if (*client).client_state.is_null() {
        return 0 as *mut llmp_broker_clientdata_t
    }
    (*(*client).client_state).id = (*broker).llmp_client_count as u32_0;
    (*client).cur_client_map =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong) as
            *mut afl_shmem_t;
    if (*client).cur_client_map.is_null() {
        printf(b"[D] [src/llmp.c:567] Could not allocate mem for client map\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as *mut llmp_broker_clientdata_t
    }
    if afl_shmem_by_str((*client).cur_client_map, shm_str, map_size).is_null()
       {
        printf(b"[D] [src/llmp.c:574] Could not map shmem \'%s\'\x00" as
                   *const u8 as *const libc::c_char, shm_str);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as *mut llmp_broker_clientdata_t
    }
    printf(b"[D] [src/llmp.c:580] Registerd new client.\x00" as *const u8 as
               *const libc::c_char);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*broker).llmp_client_count {
        let mut actual_id: u32_0 =
            (*(*(*broker).llmp_clients.offset(i as isize)).client_state).id;
        if i != actual_id as libc::c_ulong {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Inconsistent client state detected: id is %d but should be %ld\x00"
                       as *const u8 as *const libc::c_char, actual_id, i);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 28],
                                             &[libc::c_char; 28]>(b"llmp_broker_register_client\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   585 as libc::c_int);
            exit(1 as libc::c_int);
        }
        i = i.wrapping_add(1)
    }
    (*broker).llmp_client_count = (*broker).llmp_client_count.wrapping_add(1);
    // tODO: Add client map
    printf(b"[D] [src/llmp.c:595] Added clientprocess with id %d\x00" as
               *const u8 as *const libc::c_char,
           (*(*client).client_state).id);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    return client;
}
/* broker broadcast to its own page for all others to read */
#[inline]
unsafe extern "C" fn llmp_broker_handle_new_msgs(mut broker:
                                                     *mut llmp_broker_t,
                                                 mut client:
                                                     *mut llmp_broker_clientdata_t) {
    // TODO: We could memcpy a range of pending messages, instead of one by one.
  /* DBG("llmp_broker_handle_new_msgs %p %p->%u\n", broker, client, client->client_state->id); */
    let mut incoming: *mut llmp_page_t = shmem2page((*client).cur_client_map);
    let mut current_message_id: u32_0 =
        if !(*client).last_msg_broker_read.is_null() {
            (*(*client).last_msg_broker_read).message_id
        } else { 0 as libc::c_int as libc::c_uint };
    while current_message_id as libc::c_ulong != (*incoming).current_msg_id {
        let mut msg: *mut llmp_message_t =
            llmp_recv(incoming, (*client).last_msg_broker_read);
        printf(b"[D] [src/llmp.c:616] Broker send: our current_message_id for client %d (at ptr %p) is %d%s, now processing msg id %d with tag 0x%X\x00"
                   as *const u8 as *const libc::c_char,
               (*(*client).client_state).id, client, current_message_id,
               if !(*client).last_msg_broker_read.is_null() {
                   b"\x00" as *const u8 as *const libc::c_char
               } else {
                   b" (last msg was NULL)\x00" as *const u8 as
                       *const libc::c_char
               }, (*msg).message_id, (*msg).tag);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        if msg.is_null() {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : No message received but not all message ids receved! Data out of sync?\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 28],
                                             &[libc::c_char; 28]>(b"llmp_broker_handle_new_msgs\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   618 as libc::c_int);
            exit(1 as libc::c_int);
        }
        if (*msg).tag == 0xaf1e0f1 as libc::c_int as libc::c_uint {
            let mut pageinfo: *mut llmp_payload_new_page_t =
                ({
                     let mut _msg: *mut llmp_message_t = msg;
                     (if (*_msg).buf_len >=
                             ::std::mem::size_of::<llmp_payload_new_page_t>()
                                 as libc::c_ulong {
                          (*_msg).buf.as_mut_ptr()
                      } else { 0 as *mut u8_0 }) as
                         *mut llmp_payload_new_page_t
                 });
            if pageinfo.is_null() {
                printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Illegal message length for EOP (is %zu, expected %zu)\x00"
                           as *const u8 as *const libc::c_char,
                       (*msg).buf_len_padded,
                       ::std::mem::size_of::<llmp_payload_new_page_t>() as
                           libc::c_ulong);
                printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                           *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 28],
                                                 &[libc::c_char; 28]>(b"llmp_broker_handle_new_msgs\x00")).as_ptr(),
                       b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                       626 as libc::c_int);
                exit(1 as libc::c_int);
            }
            printf(b"[D] [src/llmp.c:630] Got EOP from client %d. Mapping new map.\x00"
                       as *const u8 as *const libc::c_char,
                   (*(*client).client_state).id);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            /* We can reuse the map mem space, no need to free and calloc.
      However, the pageinfo points to the map we're about to unmap.
      Copy the contents first. */
            let mut pageinfo_cpy: llmp_payload_new_page_t =
                llmp_payload_new_page_t{map_size: 0, shm_str: [0; 20],};
            memcpy(&mut pageinfo_cpy as *mut llmp_payload_new_page_t as
                       *mut libc::c_void, pageinfo as *const libc::c_void,
                   ::std::mem::size_of::<llmp_payload_new_page_t>() as
                       libc::c_ulong);
            let mut client_map: *mut afl_shmem_t = (*client).cur_client_map;
            ::std::ptr::write_volatile(&mut (*shmem2page(client_map)).save_to_unmap
                                           as *mut u16_0,
                                       1 as libc::c_int as u16_0);
            afl_shmem_deinit(client_map);
            if afl_shmem_by_str(client_map, (*pageinfo).shm_str.as_mut_ptr(),
                                (*pageinfo).map_size).is_null() {
                printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Could not get shmem by str for map %s of size %zu\x00"
                           as *const u8 as *const libc::c_char,
                       (*pageinfo).shm_str.as_mut_ptr(),
                       (*pageinfo).map_size);
                printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                           *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 28],
                                                 &[libc::c_char; 28]>(b"llmp_broker_handle_new_msgs\x00")).as_ptr(),
                       b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                       645 as libc::c_int);
                exit(1 as libc::c_int);
            }
        } else if (*msg).tag == 0xc11e471 as libc::c_int as libc::c_uint {
            printf(b"[D] [src/llmp.c:651] Will add a new client.\x00" as
                       *const u8 as *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            /* This client informs us about yet another new client
      add it to the list! Also, no need to forward this msg. */
            let mut pageinfo_0: *mut llmp_payload_new_page_t =
                ({
                     let mut _msg: *mut llmp_message_t = msg;
                     (if (*_msg).buf_len >=
                             ::std::mem::size_of::<llmp_payload_new_page_t>()
                                 as libc::c_ulong {
                          (*_msg).buf.as_mut_ptr()
                      } else { 0 as *mut u8_0 }) as
                         *mut llmp_payload_new_page_t
                 });
            if pageinfo_0.is_null() {
                printf(b"[!] WARNING: Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected %zu but got %zu\x00"
                           as *const u8 as *const libc::c_char,
                       ::std::mem::size_of::<llmp_payload_new_page_t>() as
                           libc::c_ulong, (*msg).buf_len_padded);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
            }
            /* register_client may realloc the clients, we need to find ours again */
            let mut client_id: u32_0 = (*(*client).client_state).id;
            if llmp_broker_register_client(broker,
                                           (*pageinfo_0).shm_str.as_mut_ptr(),
                                           (*pageinfo_0).map_size).is_null() {
                printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Could not register clientprocess with shm_str %s\x00"
                           as *const u8 as *const libc::c_char,
                       (*pageinfo_0).shm_str.as_mut_ptr());
                printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                           *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 28],
                                                 &[libc::c_char; 28]>(b"llmp_broker_handle_new_msgs\x00")).as_ptr(),
                       b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                       669 as libc::c_int);
                exit(1 as libc::c_int);
            }
            (*client).client_type = LLMP_CLIENT_TYPE_FOREIGN_PROCESS;
            /* find client again */
            client =
                &mut *(*broker).llmp_clients.offset(client_id as isize) as
                    *mut llmp_broker_clientdata_t
        } else {
            let mut forward_msg: bool = 1 as libc::c_int != 0;
            let mut i: size_t = 0;
            i = 0 as libc::c_int as size_t;
            while i < (*broker).msg_hook_count {
                let mut msg_hook: *mut llmp_hookdata_t =
                    &mut *(*broker).msg_hooks.offset(i as isize) as
                        *mut llmp_hookdata_t;
                forward_msg =
                    forward_msg as libc::c_int != 0 &&
                        ::std::mem::transmute::<*mut libc::c_void,
                                                Option<llmp_message_hook_func>>((*msg_hook).func).expect("non-null function pointer")(broker,
                                                                                                                                      client,
                                                                                                                                      msg,
                                                                                                                                      (*msg_hook).data)
                            as libc::c_int != 0;
                if !llmp_msg_in_page(shmem2page((*client).cur_client_map),
                                     msg) {
                    /* Special handling in case the client got exchanged inside the message_hook, for example after a crash. */
                    printf(b"[D] [src/llmp.c:689] Message hook altered the client. We\'ll yield for now.\x00"
                               as *const u8 as *const libc::c_char);
                    printf(b"\n\x00" as *const u8 as *const libc::c_char);
                    fflush(stdout);
                    return
                }
                i = i.wrapping_add(1)
            }
            if forward_msg {
                printf(b"[D] [src/llmp.c:698] Broadcasting msg with id %d, tag 0x%X\x00"
                           as *const u8 as *const libc::c_char,
                       (*msg).message_id, (*msg).tag);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                let mut out: *mut llmp_message_t =
                    llmp_broker_alloc_next(broker, (*msg).buf_len_padded);
                if out.is_null() {
                    printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error allocating %zu bytes in shmap %s\x00"
                               as *const u8 as *const libc::c_char,
                           (*msg).buf_len_padded,
                           (*_llmp_broker_current_broadcast_map(broker)).shm_str.as_mut_ptr());
                    printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                               *const u8 as *const libc::c_char,
                           (*::std::mem::transmute::<&[u8; 28],
                                                     &[libc::c_char; 28]>(b"llmp_broker_handle_new_msgs\x00")).as_ptr(),
                           b"src/llmp.c\x00" as *const u8 as
                               *const libc::c_char, 704 as libc::c_int);
                    exit(1 as libc::c_int);
                }
                /* Copy over the whole message.
        If we should need zero copy, we could instead post a link to the
        original msg with the map_id and offset. */
                printf(b"[D] [src/llmp.c:712] broker memcpy %p->%lu %p->%lu copy %lu\n\x00"
                           as *const u8 as *const libc::c_char, out,
                       (*out).buf_len_padded, msg, (*msg).buf_len_padded,
                       (::std::mem::size_of::<llmp_message_t>() as
                            libc::c_ulong).wrapping_add((*msg).buf_len_padded));
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                let mut actual_size: size_t = (*out).buf_len_padded;
                memcpy(out as *mut libc::c_void, msg as *const libc::c_void,
                       (::std::mem::size_of::<llmp_message_t>() as
                            libc::c_ulong).wrapping_add((*msg).buf_len_padded));
                (*out).buf_len_padded = actual_size;
                /* We need to replace the message ID with our own */
                let mut out_page: *mut llmp_page_t =
                    shmem2page(_llmp_broker_current_broadcast_map(broker));
                (*out).message_id =
                    (*out_page).current_msg_id.wrapping_add(1 as libc::c_int
                                                                as
                                                                libc::c_ulong)
                        as u32_0;
                if !llmp_send(out_page, out) {
                    printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error sending msg\x00"
                               as *const u8 as *const libc::c_char);
                    printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                               *const u8 as *const libc::c_char,
                           (*::std::mem::transmute::<&[u8; 28],
                                                     &[libc::c_char; 28]>(b"llmp_broker_handle_new_msgs\x00")).as_ptr(),
                           b"src/llmp.c\x00" as *const u8 as
                               *const libc::c_char, 722 as libc::c_int);
                    exit(1 as libc::c_int);
                }
                (*broker).last_msg_sent = out
            }
        }
        (*client).last_msg_broker_read = msg;
        current_message_id = (*msg).message_id
    };
}
/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
#[inline]
unsafe extern "C" fn llmp_broker_once(mut broker: *mut llmp_broker_t) {
    let mut i: u32_0 = 0;
    asm!("" : : : "memory" : "volatile");
    i = 0 as libc::c_int as u32_0;
    while (i as libc::c_ulong) < (*broker).llmp_client_count {
        let mut client: *mut llmp_broker_clientdata_t =
            &mut *(*broker).llmp_clients.offset(i as isize) as
                *mut llmp_broker_clientdata_t;
        llmp_broker_handle_new_msgs(broker, client);
        i = i.wrapping_add(1)
    };
}
/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_loop(mut broker: *mut llmp_broker_t) {
    loop  {
        asm!("" : : : "memory" : "volatile");
        llmp_broker_once(broker);
        /* 5 milis of sleep for now to not busywait at 100% */
        usleep((5 as libc::c_int * 1000 as libc::c_int) as __useconds_t);
    };
}
/* A new page will be used. Notify each registered hook in the client about this fact. */
unsafe extern "C" fn llmp_client_trigger_new_out_page_hooks(mut client:
                                                                *mut llmp_client_t) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*client).new_out_page_hook_count {
        ::std::mem::transmute::<*mut libc::c_void,
                                Option<llmp_client_new_page_hook_func>>((*(*client).new_out_page_hooks.offset(i
                                                                                                                  as
                                                                                                                  isize)).func).expect("non-null function pointer")(client,
                                                                                                                                                                    shmem2page(&mut *(*client).out_maps.offset((*client).out_map_count.wrapping_sub(1
                                                                                                                                                                                                                                                        as
                                                                                                                                                                                                                                                        libc::c_int
                                                                                                                                                                                                                                                        as
                                                                                                                                                                                                                                                        libc::c_ulong)
                                                                                                                                                                                                                   as
                                                                                                                                                                                                                   isize)),
                                                                                                                                                                    (*(*client).new_out_page_hooks.offset(i
                                                                                                                                                                                                              as
                                                                                                                                                                                                              isize)).data);
        i = i.wrapping_add(1)
    };
}
/* A wrapper around unpacking the data, calling through to the loop */
unsafe extern "C" fn _llmp_client_wrapped_loop(mut llmp_client_broker_metadata_ptr:
                                                   *mut libc::c_void)
 -> *mut libc::c_void {
    let mut metadata: *mut llmp_broker_clientdata_t =
        llmp_client_broker_metadata_ptr as *mut llmp_broker_clientdata_t;
    /* Before doing anything else:, notify registered hooks about the new page we're about to use */
    llmp_client_trigger_new_out_page_hooks((*metadata).client_state);
    /*
    if (metadata->data && (unsigned long int) metadata->data > 0x10000) {

      afl_engine_t *engine = (afl_engine_t *)metadata->data;

      if (engine->executor->funcs.init_cb) {

        DBG("Client init");

        AFL_TRY(engine->executor->funcs.init_cb(engine->executor), {

          FATAL("could not execute custom init function of the child");

        });

      }

    }

  */
    printf(b"[D] [src/llmp.c:810] Client looping\x00" as *const u8 as
               *const libc::c_char);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    (*metadata).clientloop.expect("non-null function pointer")((*metadata).client_state,
                                                               (*metadata).data);
    printf(b"[!] WARNING: Client loop exited for client %d\x00" as *const u8
               as *const libc::c_char, (*(*metadata).client_state).id);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    return 0 as *mut libc::c_void;
}
/* launch a specific client. This function is rarely needed - all registered clients will get launched at broker_run */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_launch_client(mut broker:
                                                       *mut llmp_broker_t,
                                                   mut clientdata:
                                                       *mut llmp_broker_clientdata_t)
 -> bool {
    if clientdata < (*broker).llmp_clients ||
           clientdata >
               &mut *(*broker).llmp_clients.offset((*broker).llmp_client_count.wrapping_sub(1
                                                                                                as
                                                                                                libc::c_int
                                                                                                as
                                                                                                libc::c_ulong)
                                                       as isize) as
                   *mut llmp_broker_clientdata_t {
        printf(b"[!] WARNING: Illegal client specified at ptr %p (instead of %p to %p)\x00"
                   as *const u8 as *const libc::c_char, clientdata,
               (*broker).llmp_clients,
               &mut *(*broker).llmp_clients.offset((*broker).llmp_client_count.wrapping_sub(1
                                                                                                as
                                                                                                libc::c_int
                                                                                                as
                                                                                                libc::c_ulong)
                                                       as isize) as
                   *mut llmp_broker_clientdata_t);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        return 0 as libc::c_int != 0
    }
    if (*clientdata).client_type as libc::c_uint ==
           LLMP_CLIENT_TYPE_CHILD_PROCESS as libc::c_int as libc::c_uint {
        if (*clientdata).pid != 0 {
            printf(b"[!] WARNING: Tried to relaunch already running client. Set ->pid to 0 if this is what you want.\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            return 0 as libc::c_int != 0
        }
        printf(b"[D] [src/llmp.c:838] Launching new client process\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        let mut child_id: libc::c_int = fork();
        if child_id < 0 as libc::c_int {
            printf(b"[!] WARNING: Could not fork\x00" as *const u8 as
                       *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            return 0 as libc::c_int != 0
        } else {
            if child_id == 0 as libc::c_int {
                /* child */
                /*
      s32 dev_null_fd = open("/dev/null", O_WRONLY);
      dup2(dev_null_fd, 2);
      close(dev_null_fd);
      */
                /* in the child, start loop, exit afterwards. */
                printf(b"[D] [src/llmp.c:855] LLMP child process started\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                printf(b"[D] [src/llmp.c:856] Fork child loop\x00" as
                           *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                _llmp_client_wrapped_loop(clientdata as *mut libc::c_void);
                printf(b"[D] [src/llmp.c:858] Fork child loop exited\x00" as
                           *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                exit(1 as libc::c_int);
            }
        }
        /* parent */
        (*clientdata).pid = child_id;
        return 1 as libc::c_int != 0
    } else {
        if (*clientdata).client_type as libc::c_uint ==
               LLMP_CLIENT_TYPE_PTHREAD as libc::c_int as libc::c_uint {
            /* Got a pthread -> threaded client. Spwan. :) */
            let mut s: libc::c_int =
                pthread_create((*clientdata).pthread,
                               0 as *const pthread_attr_t,
                               Some(_llmp_client_wrapped_loop as
                                        unsafe extern "C" fn(_:
                                                                 *mut libc::c_void)
                                            -> *mut libc::c_void),
                               clientdata as *mut libc::c_void);
            if s != 0 {
                // TODO: Better Error-handling! :)
                printf(b"[!] WARNING: Error creating thread\x00" as *const u8
                           as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                return 0 as libc::c_int != 0
            }
        } else {
            printf(b"[!] WARNING: Tried to spawn llmp child with unknown thread type.\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            return 0 as libc::c_int != 0
        }
    }
    return 1 as libc::c_int != 0;
}
/* Kicks off all threaded clients in the brackground, using pthreads */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_launch_clientloops(mut broker:
                                                            *mut llmp_broker_t)
 -> bool {
    let mut i: size_t = 0;
    /* We never want pthread clients before we fork, libraries may do mutexes,
   * etc... */
    i = 0 as libc::c_int as size_t;
    while i < (*broker).llmp_client_count {
        if (*(*broker).llmp_clients.offset(i as isize)).client_type as
               libc::c_uint ==
               LLMP_CLIENT_TYPE_CHILD_PROCESS as libc::c_int as libc::c_uint {
            if !llmp_broker_launch_client(broker,
                                          &mut *(*broker).llmp_clients.offset(i
                                                                                  as
                                                                                  isize))
               {
                printf(b"[!] WARNING: Could not launch all clients\x00" as
                           *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                return 0 as libc::c_int != 0
            }
        }
        i = i.wrapping_add(1)
    }
    /* Now spawn pthread clients */
    i = 0 as libc::c_int as size_t;
    while i < (*broker).llmp_client_count {
        if (*(*broker).llmp_clients.offset(i as isize)).client_type as
               libc::c_uint ==
               LLMP_CLIENT_TYPE_PTHREAD as libc::c_int as libc::c_uint {
            if !llmp_broker_launch_client(broker,
                                          &mut *(*broker).llmp_clients.offset(i
                                                                                  as
                                                                                  isize))
               {
                printf(b"[!] WARNING: Could not launch all clients\x00" as
                           *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                return 0 as libc::c_int != 0
            }
        }
        i = i.wrapping_add(1)
    }
    return 1 as libc::c_int != 0;
}
/* The broker walks all pages and looks for changes, then broadcasts them on
 its own shared page.
 Never returns. */
/* Start all threads and the main broker.
Same as llmp_broker_launch_threaded clients();
Never returns. */
/* Start all threads and the main broker. Never returns. */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_run(mut broker: *mut llmp_broker_t) {
    llmp_broker_launch_clientloops(broker);
    llmp_broker_loop(broker);
}
/*
 For non zero-copy, we want to get rid of old pages with duplicate messages
 eventually. This function This funtion sees if we can unallocate older pages.
 The broker would have informed us by setting the save_to_unmap-flag.
*/
unsafe extern "C" fn llmp_client_prune_old_pages(mut client:
                                                     *mut llmp_client_t) {
    let mut current_map: *mut u8_0 =
        (*(*client).out_maps.offset((*client).out_map_count.wrapping_sub(1 as
                                                                             libc::c_int
                                                                             as
                                                                             libc::c_ulong)
                                        as isize)).map;
    /* look for pages that are save_to_unmap, then unmap them. */
    while (*(*client).out_maps.offset(0 as libc::c_int as isize)).map !=
              current_map &&
              (*shmem2page(&mut *(*client).out_maps.offset(0 as libc::c_int as
                                                               isize))).save_to_unmap
                  as libc::c_int != 0 {
        printf(b"[D] [src/llmp.c:954] Page %ld is save to unmap. Unmapping...\x00"
                   as *const u8 as *const libc::c_char,
               (*shmem2page(&mut *(*client).out_maps.offset(0 as libc::c_int
                                                                as
                                                                isize))).current_msg_id);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        /* This page is save to unmap. The broker already reads or read it. */
        printf(b"[D] [src/llmp.c:957] Unmap shared map %s from client\x00" as
                   *const u8 as *const libc::c_char,
               (*(*client).out_maps.offset(0 as libc::c_int as
                                               isize)).shm_str.as_mut_ptr());
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_shmem_deinit(&mut *(*client).out_maps.offset(0 as libc::c_int as
                                                             isize));
        /* We remove at the start, move the other pages back. */
        memmove((*client).out_maps as *mut libc::c_void,
                (*client).out_maps.offset(1 as libc::c_int as isize) as
                    *const libc::c_void,
                (*client).out_map_count.wrapping_sub(1 as libc::c_int as
                                                         libc::c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem_t>()
                                                                                         as
                                                                                         libc::c_ulong));
        (*client).out_map_count = (*client).out_map_count.wrapping_sub(1)
    };
}
/* We don't have any space. Send eop, the reset to beginning of ringbuf */
unsafe extern "C" fn llmp_client_handle_out_eop(mut client:
                                                    *mut llmp_client_t)
 -> bool {
    printf(b"[D] [src/llmp.c:970] Sending client EOP for client %d\x00" as
               *const u8 as *const libc::c_char, (*client).id);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    (*client).out_maps =
        llmp_handle_out_eop((*client).out_maps, &mut (*client).out_map_count,
                            &mut (*client).last_msg_sent);
    if (*client).out_maps.is_null() {
        printf(b"[D] [src/llmp.c:974] An error occurred when handling client eop\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    /* Prune old pages!
    This is a good time to see if we can unallocate older pages.
    The broker would have informed us by setting the flag
  */
    llmp_client_prune_old_pages(client);
    /* So we got a new page. Inform potential hooks */
    llmp_client_trigger_new_out_page_hooks(client);
    return 1 as libc::c_int != 0;
}
/* A client receives a broadcast message. Returns null if no message is
 * availiable */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_recv(mut client: *mut llmp_client_t)
 -> *mut llmp_message_t {
    let mut msg: *mut llmp_message_t = 0 as *mut llmp_message_t;
    loop  {
        msg =
            llmp_recv(shmem2page((*client).current_broadcast_map),
                      (*client).last_msg_recvd);
        if msg.is_null() { return 0 as *mut llmp_message_t }
        (*client).last_msg_recvd = msg;
        if (*msg).tag as libc::c_longlong == 0xdeadaf as libc::c_longlong {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: Read unallocated msg\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 17],
                                             &[libc::c_char; 17]>(b"llmp_client_recv\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   1006 as libc::c_int);
            exit(1 as libc::c_int);
        } else {
            if (*msg).tag == 0xaf1e0f1 as libc::c_int as libc::c_uint {
                /* we reached the end of the current page.
      We'll init a new page but can reuse the mem are of the current map.
      However, we cannot use the message if we deinit its page, so let's copy */
                let mut pageinfo_cpy: llmp_payload_new_page_t =
                    llmp_payload_new_page_t{map_size: 0, shm_str: [0; 20],};
                let mut broadcast_map: *mut afl_shmem_t =
                    (*client).current_broadcast_map;
                let mut pageinfo: *mut llmp_payload_new_page_t =
                    ({
                         let mut _msg: *mut llmp_message_t = msg;
                         (if (*_msg).buf_len >=
                                 ::std::mem::size_of::<llmp_payload_new_page_t>()
                                     as libc::c_ulong {
                              (*_msg).buf.as_mut_ptr()
                          } else { 0 as *mut u8_0 }) as
                             *mut llmp_payload_new_page_t
                     });
                if pageinfo.is_null() {
                    printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Illegal message length for EOP (is %zu, expected %zu)\x00"
                               as *const u8 as *const libc::c_char,
                           (*msg).buf_len_padded,
                           ::std::mem::size_of::<llmp_payload_new_page_t>() as
                               libc::c_ulong);
                    printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                               *const u8 as *const libc::c_char,
                           (*::std::mem::transmute::<&[u8; 17],
                                                     &[libc::c_char; 17]>(b"llmp_client_recv\x00")).as_ptr(),
                           b"src/llmp.c\x00" as *const u8 as
                               *const libc::c_char, 1020 as libc::c_int);
                    exit(1 as libc::c_int);
                }
                memcpy(&mut pageinfo_cpy as *mut llmp_payload_new_page_t as
                           *mut libc::c_void, pageinfo as *const libc::c_void,
                       ::std::mem::size_of::<llmp_payload_new_page_t>() as
                           libc::c_ulong);
                printf(b"[D] [src/llmp.c:1026] Got EOP from broker. Mapping new map.\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                /* Never read by broker broker: shmem2page(map)->save_to_unmap = true; */
                afl_shmem_deinit(broadcast_map);
                if afl_shmem_by_str((*client).current_broadcast_map,
                                    (*pageinfo).shm_str.as_mut_ptr(),
                                    (*pageinfo).map_size).is_null() {
                    printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Could not get shmem by str for map %s of size %zu\x00"
                               as *const u8 as *const libc::c_char,
                           (*pageinfo).shm_str.as_mut_ptr(),
                           (*pageinfo).map_size);
                    printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                               *const u8 as *const libc::c_char,
                           (*::std::mem::transmute::<&[u8; 17],
                                                     &[libc::c_char; 17]>(b"llmp_client_recv\x00")).as_ptr(),
                           b"src/llmp.c\x00" as *const u8 as
                               *const libc::c_char, 1033 as libc::c_int);
                    exit(1 as libc::c_int);
                }
            } else { return msg }
        }
    };
}
/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_recv_blocking(mut client:
                                                       *mut llmp_client_t)
 -> *mut llmp_message_t {
    let mut page: *mut llmp_page_t =
        shmem2page((*client).current_broadcast_map);
    loop  {
        asm!("" : : : "memory" : "volatile");
        /* busy-wait for a new msg_id to show up in the page */
        if (*page).current_msg_id !=
               (if !(*client).last_msg_recvd.is_null() {
                    (*(*client).last_msg_recvd).message_id
                } else { 0 as libc::c_int as libc::c_uint }) as libc::c_ulong
           {
            printf(b"[D] [src/llmp.c:1060] Blocking read got new page->current_msg_id %ld (last msg id was %d)\x00"
                       as *const u8 as *const libc::c_char,
                   (*page).current_msg_id,
                   if !(*client).last_msg_recvd.is_null() {
                       (*(*client).last_msg_recvd).message_id
                   } else { 0 as libc::c_int as libc::c_uint });
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            let mut ret: *mut llmp_message_t = llmp_client_recv(client);
            if !ret.is_null() {
                printf(b"[D] [src/llmp.c:1065] blocking got new msg %d\x00" as
                           *const u8 as *const libc::c_char,
                       (*ret).message_id);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                return ret
            }
            if !(*client).last_msg_recvd.is_null() &&
                   (*(*client).last_msg_recvd).tag ==
                       0xaf1e0f1 as libc::c_int as libc::c_uint {
                printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: client recv returned null unexpectedly\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                           *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 26],
                                                 &[libc::c_char; 26]>(b"llmp_client_recv_blocking\x00")).as_ptr(),
                       b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                       1073 as libc::c_int);
                exit(1 as libc::c_int);
            }
            /* last msg will exist, even if EOP was handled internally */
            page = shmem2page((*client).current_broadcast_map)
        }
    };
}
/* The current page could have changed in recv (EOP) */
/* Alloc the next message, internally handling end of page by allocating a new one. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_alloc_next(mut client:
                                                    *mut llmp_client_t,
                                                mut size: size_t)
 -> *mut llmp_message_t {
    if client.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : client is NULL\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 23],
                                         &[libc::c_char; 23]>(b"llmp_client_alloc_next\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               1097 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut msg: *mut llmp_message_t = 0 as *mut llmp_message_t;
    msg =
        llmp_alloc_next(shmem2page(&mut *(*client).out_maps.offset((*client).out_map_count.wrapping_sub(1
                                                                                                            as
                                                                                                            libc::c_int
                                                                                                            as
                                                                                                            libc::c_ulong)
                                                                       as
                                                                       isize)),
                        (*client).last_msg_sent, size);
    if msg.is_null() {
        let mut last_map_count: size_t = (*client).out_map_count;
        /* Page is full -> Tell broker and start from the beginning.
    Also, pray the broker got all messaes we're overwriting. :) */
        if !llmp_client_handle_out_eop(client) {
            printf(b"[D] [src/llmp.c:1111] BUG: Error sending EOP\x00" as
                       *const u8 as *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            return 0 as *mut llmp_message_t
        }
        if (*client).out_map_count == last_map_count ||
               (*(*shmem2page(&mut *(*client).out_maps.offset((*client).out_map_count.wrapping_sub(1
                                                                                                       as
                                                                                                       libc::c_int
                                                                                                       as
                                                                                                       libc::c_ulong)
                                                                  as
                                                                  isize))).messages.as_mut_ptr()).tag
                   as libc::c_longlong != 0xdeadaf as libc::c_longlong {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error in handle_out_eop\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"llmp_client_alloc_next\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   1119 as libc::c_int);
            exit(1 as libc::c_int);
        }
        /* The client_out_map will have been changed by llmp_handle_out_eop. Don't
     * alias.
     */
        msg =
            llmp_alloc_next(shmem2page(&mut *(*client).out_maps.offset((*client).out_map_count.wrapping_sub(1
                                                                                                                as
                                                                                                                libc::c_int
                                                                                                                as
                                                                                                                libc::c_ulong)
                                                                           as
                                                                           isize)),
                            0 as *mut llmp_message_t, size);
        if msg.is_null() {
            printf(b"[D] [src/llmp.c:1129] BUG: Something went wrong allocating a msg in the shmap\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            return 0 as *mut llmp_message_t
        }
    }
    (*msg).sender = (*client).id;
    (*msg).message_id =
        if !(*client).last_msg_sent.is_null() {
            (*(*client).last_msg_sent).message_id.wrapping_add(1 as
                                                                   libc::c_int
                                                                   as
                                                                   libc::c_uint)
        } else { 1 as libc::c_int as libc::c_uint };
    /* DBG("Allocated message at loc %p with buflen %ld", msg, msg->buf_len_padded); */
    return msg;
}
/* Cancel send of the next message, this allows us to allocate a new message without sending this one. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_cancel(mut client: *mut llmp_client_t,
                                            mut msg: *mut llmp_message_t) {
    /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
   * msg->buf_len_padded); */
    let mut page: *mut llmp_page_t =
        shmem2page(&mut *(*client).out_maps.offset((*client).out_map_count.wrapping_sub(1
                                                                                            as
                                                                                            libc::c_int
                                                                                            as
                                                                                            libc::c_ulong)
                                                       as isize));
    if !llmp_msg_in_page(page, msg) {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: Trying to cancel msg that\'s not in page! (%p not in %p with size %ld)\x00"
                   as *const u8 as *const libc::c_char, msg, page,
               (*page).size_total);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 19],
                                         &[libc::c_char; 19]>(b"llmp_client_cancel\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               1155 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*msg).tag = 0xdeadaf as libc::c_longlong as u32_0;
    (*page).size_used =
        ((*page).size_used as
             libc::c_ulong).wrapping_sub((*msg).buf_len_padded.wrapping_add(::std::mem::size_of::<llmp_message_t>()
                                                                                as
                                                                                libc::c_ulong))
            as size_t as size_t;
}
/* Commits a msg to the client's out ringbuf */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_send(mut client_state:
                                              *mut llmp_client_t,
                                          mut msg: *mut llmp_message_t)
 -> bool {
    printf(b"[D] [src/llmp.c:1169] Client %d sends new msg at %p with tag 0x%X and size %ld\x00"
               as *const u8 as *const libc::c_char, (*client_state).id, msg,
           (*msg).tag, (*msg).buf_len_padded);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut page: *mut llmp_page_t =
        shmem2page(&mut *(*client_state).out_maps.offset((*client_state).out_map_count.wrapping_sub(1
                                                                                                        as
                                                                                                        libc::c_int
                                                                                                        as
                                                                                                        libc::c_ulong)
                                                             as isize));
    if !llmp_msg_in_page(page, msg) {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: Message to send not in correct page (%p not in %p with size %ld)\x00"
                   as *const u8 as *const libc::c_char, msg, page,
               (*page).size_total);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 17],
                                         &[libc::c_char; 17]>(b"llmp_client_send\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               1176 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut ret: bool = llmp_send(page, msg);
    (*client_state).last_msg_sent = msg;
    return ret;
}
/* A simple client that, on connect, reads the new client's shmap str and
 * writes the broker's initial map str */
#[no_mangle]
pub unsafe extern "C" fn llmp_clientloop_process_server(mut client_state:
                                                            *mut llmp_client_t,
                                                        mut data:
                                                            *mut libc::c_void) {
    let mut port: libc::c_int = data as size_t as libc::c_int;
    let mut initial_broadcast_map: llmp_payload_new_page_t =
        {
            let mut init =
                llmp_payload_new_page{map_size: 0 as libc::c_int as size_t,
                                      shm_str: [0; 20],};
            init
        };
    initial_broadcast_map.map_size =
        (*(*client_state).current_broadcast_map).map_size;
    memcpy(initial_broadcast_map.shm_str.as_mut_ptr() as *mut libc::c_void,
           (*(*client_state).current_broadcast_map).shm_str.as_mut_ptr() as
               *const libc::c_void, 20 as libc::c_int as libc::c_ulong);
    let mut serv_addr: sockaddr_in =
        {
            let mut init =
                sockaddr_in{sin_family: 0 as libc::c_int as sa_family_t,
                            sin_port: 0,
                            sin_addr: in_addr{s_addr: 0,},
                            sin_zero: [0; 8],};
            init
        };
    let mut listenfd: libc::c_int =
        socket(2 as libc::c_int, SOCK_STREAM as libc::c_int,
               0 as libc::c_int);
    serv_addr.sin_family = 2 as libc::c_int as sa_family_t;
    serv_addr.sin_addr.s_addr = htonl(0x7f000001 as libc::c_int as in_addr_t);
    /* port 2801 */
    serv_addr.sin_port = htons(port as uint16_t);
    let mut backoff: uint32_t = 2 as libc::c_int as uint32_t;
    while bind(listenfd, &mut serv_addr as *mut sockaddr_in as *mut sockaddr,
               ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                   socklen_t) == -(1 as libc::c_int) {
        printf(b"[!] WARNING: Could not bind to %d! Retrying in %d seconds.\x00"
                   as *const u8 as *const libc::c_char, port, backoff);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        sleep(backoff);
        backoff =
            (backoff as
                 libc::c_uint).wrapping_mul(2 as libc::c_int as libc::c_uint)
                as uint32_t as uint32_t
    }
    if listen(listenfd, 10 as libc::c_int) == -(1 as libc::c_int) {
        fflush(stdout);
        printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Coult not listen to %d\x00" as
                   *const u8 as *const libc::c_char, port);
        printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 31],
                                         &[libc::c_char; 31]>(b"llmp_clientloop_process_server\x00")).as_ptr(),
               b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
               1216 as libc::c_int);
        printf(b"       OS message : %s\n\x00" as *const u8 as
                   *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    let mut msg: *mut llmp_message_t =
        llmp_client_alloc_next(client_state,
                               ::std::mem::size_of::<llmp_payload_new_page_t>()
                                   as libc::c_ulong);
    loop  {
        if msg.is_null() {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error allocating new client msg in tcp client!\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 31],
                                             &[libc::c_char; 31]>(b"llmp_clientloop_process_server\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   1222 as libc::c_int);
            exit(1 as libc::c_int);
        }
        (*msg).tag = 0xc11e471 as libc::c_int as u32_0;
        let mut payload: *mut llmp_payload_new_page_t =
            (*msg).buf.as_mut_ptr() as *mut llmp_payload_new_page_t;
        let mut connfd: libc::c_int =
            accept(listenfd, 0 as *mut libc::c_void as *mut sockaddr,
                   0 as *mut socklen_t);
        if connfd == -(1 as libc::c_int) {
            printf(b"[!] WARNING: Error on accept\x00" as *const u8 as
                       *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
        } else {
            printf(b"[D] [src/llmp.c:1235] New clientprocess connected\x00" as
                       *const u8 as *const libc::c_char);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
            if write(connfd,
                     &mut initial_broadcast_map as
                         *mut llmp_payload_new_page_t as *const libc::c_void,
                     ::std::mem::size_of::<llmp_payload_new_page_t>() as
                         libc::c_ulong) as libc::c_ulong !=
                   ::std::mem::size_of::<llmp_payload_new_page_t>() as
                       libc::c_ulong {
                printf(b"[!] WARNING: Socket_client: TCP client disconnected immediately\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                close(connfd);
            } else {
                let mut rlen_total: size_t = 0 as libc::c_int as size_t;
                while rlen_total <
                          ::std::mem::size_of::<llmp_payload_new_page_t>() as
                              libc::c_ulong {
                    let mut rlen: ssize_t =
                        read(connfd,
                             payload.offset(rlen_total as isize) as
                                 *mut libc::c_void,
                             (::std::mem::size_of::<llmp_payload_new_page_t>()
                                  as libc::c_ulong).wrapping_sub(rlen_total));
                    if rlen < 0 as libc::c_int as libc::c_long {
                        // TODO: Handle EINTR?
                        printf(b"[!] WARNING: No complete map str receved from TCP client\x00"
                                   as *const u8 as *const libc::c_char);
                        printf(b"\n\x00" as *const u8 as *const libc::c_char);
                        close(connfd);
                    } else {
                        rlen_total =
                            (rlen_total as
                                 libc::c_ulong).wrapping_add(rlen as
                                                                 libc::c_ulong)
                                as size_t as size_t
                    }
                }
                close(connfd);
                printf(b"[D] [src/llmp.c:1265] Got new client with map id %s and size %ld\x00"
                           as *const u8 as *const libc::c_char,
                       (*payload).shm_str.as_mut_ptr(), (*payload).map_size);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
                fflush(stdout);
                if !llmp_client_send(client_state, msg) {
                    printf(b"\x1b[?25h\n[-] PROGRAM ABORT : BUG: Error sending incoming tcp msg to broker\x00"
                               as *const u8 as *const libc::c_char);
                    printf(b"\n         Location : %s(), %s:%u\n\n\x00" as
                               *const u8 as *const libc::c_char,
                           (*::std::mem::transmute::<&[u8; 31],
                                                     &[libc::c_char; 31]>(b"llmp_clientloop_process_server\x00")).as_ptr(),
                           b"src/llmp.c\x00" as *const u8 as
                               *const libc::c_char, 1267 as libc::c_int);
                    exit(1 as libc::c_int);
                }
                msg =
                    llmp_client_alloc_next(client_state,
                                           ::std::mem::size_of::<llmp_payload_new_page_t>()
                                               as libc::c_ulong)
            }
        }
    };
}
/* Creates a new, unconnected, client state */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_new_unconnected() -> *mut llmp_client_t {
    let mut client_state: *mut llmp_client_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<llmp_client_t>() as libc::c_ulong) as
            *mut llmp_client_t;
    (*client_state).current_broadcast_map =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong) as
            *mut afl_shmem_t;
    if (*client_state).current_broadcast_map.is_null() {
        printf(b"[D] [src/llmp.c:1283] Could not allocate mem\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as *mut llmp_client_t
    }
    (*client_state).out_maps =
        afl_realloc((*client_state).out_maps as *mut libc::c_void,
                    (1 as libc::c_int as
                         libc::c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem_t>()
                                                         as libc::c_ulong)) as
            *mut afl_shmem_t;
    if (*client_state).out_maps.is_null() {
        printf(b"[D] [src/llmp.c:1290] Could not allocate memory\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        free((*client_state).current_broadcast_map as *mut libc::c_void);
        free(client_state as *mut libc::c_void);
        return 0 as *mut llmp_client_t
    }
    (*client_state).out_map_count = 1 as libc::c_int as size_t;
    if llmp_new_page_shmem(&mut *(*client_state).out_maps.offset(0 as
                                                                     libc::c_int
                                                                     as
                                                                     isize),
                           (*client_state).id as size_t,
                           ((1 as libc::c_int) << 28 as libc::c_int) as
                               size_t).is_null() {
        printf(b"[D] [src/llmp.c:1301] Could not create sharedmem\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_free((*client_state).out_maps as *mut libc::c_void);
        free((*client_state).current_broadcast_map as *mut libc::c_void);
        free(client_state as *mut libc::c_void);
        return 0 as *mut llmp_client_t
    }
    (*client_state).new_out_page_hook_count = 0 as libc::c_int as size_t;
    (*client_state).new_out_page_hooks = 0 as *mut llmp_hookdata_t;
    return client_state;
}
/* Destroys the given cient state */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_delete(mut client_state:
                                                *mut llmp_client_t) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*client_state).out_map_count {
        afl_shmem_deinit(&mut *(*client_state).out_maps.offset(i as isize));
        i = i.wrapping_add(1)
    }
    afl_free((*client_state).out_maps as *mut libc::c_void);
    (*client_state).out_maps = 0 as *mut afl_shmem_t;
    (*client_state).out_map_count = 0 as libc::c_int as size_t;
    afl_free((*client_state).new_out_page_hooks as *mut libc::c_void);
    (*client_state).new_out_page_hooks = 0 as *mut llmp_hookdata_t;
    (*client_state).new_out_page_hook_count = 0 as libc::c_int as size_t;
    afl_shmem_deinit((*client_state).current_broadcast_map);
    free((*client_state).current_broadcast_map as *mut libc::c_void);
    (*client_state).current_broadcast_map = 0 as *mut afl_shmem_t;
    free(client_state as *mut libc::c_void);
}
/* Creates a new client process that will connect to the given port */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_new(mut port: libc::c_int)
 -> *mut llmp_client_t {
    let mut client_map_msg: llmp_payload_new_page_t =
        llmp_payload_new_page_t{map_size: 0, shm_str: [0; 20],};
    let mut broker_map_msg: llmp_payload_new_page_t =
        llmp_payload_new_page_t{map_size: 0, shm_str: [0; 20],};
    let mut rlen_total: size_t = 0;
    let mut current_block: u64;
    let mut connfd: libc::c_int = 0 as libc::c_int;
    let mut servaddr: sockaddr_in =
        {
            let mut init =
                sockaddr_in{sin_family: 0 as libc::c_int as sa_family_t,
                            sin_port: 0,
                            sin_addr: in_addr{s_addr: 0,},
                            sin_zero: [0; 8],};
            init
        };
    let mut client_state: *mut llmp_client_t = llmp_client_new_unconnected();
    (*client_state).current_broadcast_map =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong) as
            *mut afl_shmem_t;
    if (*client_state).current_broadcast_map.is_null() {
        llmp_client_delete(client_state);
        printf(b"[D] [src/llmp.c:1353] Could not allocate mem\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as *mut llmp_client_t
    }
    (*client_state).out_maps =
        afl_realloc((*client_state).out_maps as *mut libc::c_void,
                    (1 as libc::c_int as
                         libc::c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem_t>()
                                                         as libc::c_ulong)) as
            *mut afl_shmem_t;
    if (*client_state).out_maps.is_null() {
        printf(b"[D] [src/llmp.c:1360] Could not allocate memory\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        free((*client_state).current_broadcast_map as *mut libc::c_void);
        free(client_state as *mut libc::c_void);
        return 0 as *mut llmp_client_t
    }
    (*client_state).out_map_count = 1 as libc::c_int as size_t;
    if llmp_new_page_shmem(&mut *(*client_state).out_maps.offset(0 as
                                                                     libc::c_int
                                                                     as
                                                                     isize),
                           (*client_state).id as size_t,
                           ((1 as libc::c_int) << 28 as libc::c_int) as
                               size_t).is_null() {
        printf(b"[D] [src/llmp.c:1371] Could not create sharedmem\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
    } else {
        // socket create and varification
        connfd =
            socket(2 as libc::c_int, SOCK_STREAM as libc::c_int,
                   0 as libc::c_int);
        if connfd == -(1 as libc::c_int) {
            fflush(stdout);
            printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Unable to create socket\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                       *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 16],
                                             &[libc::c_char; 16]>(b"llmp_client_new\x00")).as_ptr(),
                   b"src/llmp.c\x00" as *const u8 as *const libc::c_char,
                   1378 as libc::c_int);
            printf(b"       OS message : %s\n\x00" as *const u8 as
                       *const libc::c_char, strerror(*__errno_location()));
            exit(1 as libc::c_int);
        }
        servaddr.sin_family = 2 as libc::c_int as sa_family_t;
        servaddr.sin_addr.s_addr =
            inet_addr(b"127.0.0.1\x00" as *const u8 as *const libc::c_char);
        servaddr.sin_port = htons(port as uint16_t);
        if connect(connfd, &mut servaddr as *mut sockaddr_in as *mut sockaddr,
                   ::std::mem::size_of::<sockaddr_in>() as libc::c_ulong as
                       socklen_t) != 0 as libc::c_int {
            printf(b"[D] [src/llmp.c:1388] Unable to connect to broker at localhost:%d, make sure it\'s running and has a port exposed\x00"
                       as *const u8 as *const libc::c_char, port);
            printf(b"\n\x00" as *const u8 as *const libc::c_char);
            fflush(stdout);
        } else {
            client_map_msg =
                llmp_payload_new_page_t{map_size: 0, shm_str: [0; 20],};
            broker_map_msg =
                {
                    let mut init =
                        llmp_payload_new_page{map_size:
                                                  0 as libc::c_int as size_t,
                                              shm_str: [0; 20],};
                    init
                };
            client_map_msg.map_size =
                (*(*client_state).out_maps.offset(0 as libc::c_int as
                                                      isize)).map_size;
            memcpy(client_map_msg.shm_str.as_mut_ptr() as *mut libc::c_void,
                   (*(*client_state).out_maps.offset(0 as libc::c_int as
                                                         isize)).shm_str.as_mut_ptr()
                       as *const libc::c_void,
                   20 as libc::c_int as libc::c_ulong);
            if write(connfd,
                     &mut client_map_msg as *mut llmp_payload_new_page_t as
                         *const libc::c_void,
                     ::std::mem::size_of::<llmp_payload_new_page_t>() as
                         libc::c_ulong) as libc::c_ulong !=
                   ::std::mem::size_of::<llmp_payload_new_page_t>() as
                       libc::c_ulong {
                afl_shmem_deinit(&mut *(*client_state).out_maps.offset(0 as
                                                                           libc::c_int
                                                                           as
                                                                           isize));
                free(client_state as *mut libc::c_void);
                close(connfd);
                return 0 as *mut llmp_client_t
            }
            rlen_total = 0 as libc::c_int as size_t;
            loop  {
                if !(rlen_total <
                         ::std::mem::size_of::<llmp_payload_new_page_t>() as
                             libc::c_ulong) {
                    current_block = 6243635450180130569;
                    break ;
                }
                let mut rlen: ssize_t =
                    read(connfd,
                         (&mut broker_map_msg as
                              *mut llmp_payload_new_page_t).offset(rlen_total
                                                                       as
                                                                       isize)
                             as *mut libc::c_void,
                         (::std::mem::size_of::<llmp_payload_new_page_t>() as
                              libc::c_ulong).wrapping_sub(rlen_total));
                if rlen < 0 as libc::c_int as libc::c_long {
                    // TODO: Handle EINTR?
                    printf(b"[D] [src/llmp.c:1415] Got short response from broker via TCP\x00"
                               as *const u8 as *const libc::c_char);
                    printf(b"\n\x00" as *const u8 as *const libc::c_char);
                    fflush(stdout);
                    close(connfd);
                    afl_shmem_deinit(&mut *(*client_state).out_maps.offset(0
                                                                               as
                                                                               libc::c_int
                                                                               as
                                                                               isize));
                    current_block = 11053096150074480450;
                    break ;
                } else {
                    rlen_total =
                        (rlen_total as
                             libc::c_ulong).wrapping_add(rlen as
                                                             libc::c_ulong) as
                            size_t as size_t
                }
            }
            match current_block {
                11053096150074480450 => { }
                _ => {
                    close(connfd);
                    if afl_shmem_by_str((*client_state).current_broadcast_map,
                                        broker_map_msg.shm_str.as_mut_ptr(),
                                        broker_map_msg.map_size).is_null() {
                        // TODO: Handle EINTR?
                        printf(b"[D] [src/llmp.c:1431] Could not allocate shmem\x00"
                                   as *const u8 as *const libc::c_char);
                        printf(b"\n\x00" as *const u8 as *const libc::c_char);
                        fflush(stdout);
                        afl_shmem_deinit(&mut *(*client_state).out_maps.offset(0
                                                                                   as
                                                                                   libc::c_int
                                                                                   as
                                                                                   isize));
                    } else { return client_state }
                }
            }
        }
    }
    llmp_client_delete(client_state);
    return 0 as *mut llmp_client_t;
}
/* Register a new forked/child client.
Client thread will be called with llmp_client_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_register_childprocess_clientloop(mut broker:
                                                                          *mut llmp_broker_t,
                                                                      mut clientloop:
                                                                          llmp_clientloop_func,
                                                                      mut data:
                                                                          *mut libc::c_void)
 -> bool {
    let mut client_map: afl_shmem_t =
        {
            let mut init =
                afl_shmem{shm_str: [0; 20],
                          shm_id: 0,
                          map: 0 as *mut u8_0,
                          map_size: 0,};
            init
        };
    if llmp_new_page_shmem(&mut client_map, (*broker).llmp_client_count,
                           ((1 as libc::c_int) << 28 as libc::c_int) as
                               size_t).is_null() {
        printf(b"[D] [src/llmp.c:1457] Failed to set up shmem for new client.\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    let mut client: *mut llmp_broker_clientdata_t =
        llmp_broker_register_client(broker, client_map.shm_str.as_mut_ptr(),
                                    client_map.map_size);
    if client.is_null() {
        printf(b"[D] [src/llmp.c:1465] Could not register threaded client\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_shmem_deinit(&mut client_map);
        return 0 as libc::c_int != 0
    }
    (*client).clientloop = clientloop;
    (*client).data = data;
    (*client).client_type = LLMP_CLIENT_TYPE_CHILD_PROCESS;
    /* Copy the already allocated shmem to the client state */
    (*(*client).client_state).out_maps =
        afl_realloc((*(*client).client_state).out_maps as *mut libc::c_void,
                    ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong) as
            *mut afl_shmem_t;
    if (*(*client).client_state).out_maps.is_null() {
        printf(b"[D] [src/llmp.c:1478] Could not alloc mem for client map\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_shmem_deinit(&mut client_map);
        afl_shmem_deinit((*client).cur_client_map);
        /* "Unregister" by subtracting the client from count */
        (*broker).llmp_client_count =
            (*broker).llmp_client_count.wrapping_sub(1);
        return 0 as libc::c_int != 0
    }
    memcpy((*(*client).client_state).out_maps as *mut libc::c_void,
           &mut client_map as *mut afl_shmem_t as *const libc::c_void,
           ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong);
    (*(*client).client_state).out_map_count = 1 as libc::c_int as size_t;
    /* Each client starts with the very first map.
  They should then iterate through all maps once and work on all old messages.
  */
    (*(*client).client_state).current_broadcast_map =
        &mut *(*broker).broadcast_maps.offset(0 as libc::c_int as isize) as
            *mut afl_shmem_t;
    (*(*client).client_state).out_map_count = 1 as libc::c_int as size_t;
    printf(b"[D] [src/llmp.c:1496] Registered threaded client with id %d (loop func at %p)\x00"
               as *const u8 as *const libc::c_char,
           (*(*client).client_state).id, (*client).clientloop);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    return 1 as libc::c_int != 0;
}
/* Register a new pthread/threaded client.
Client thread will be called with llmp_client_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_register_threaded_clientloop(mut broker:
                                                                      *mut llmp_broker_t,
                                                                  mut clientloop:
                                                                      llmp_clientloop_func,
                                                                  mut data:
                                                                      *mut libc::c_void)
 -> bool {
    /* We do a little dance with two sharedmaps, as the threaded clients
    reuse the client_state struct as they share the heap. If we were to
    treat threads and processes differently, it'd get too complex, so
    let's just map the sharedmem twice into this process, and be done */
    let mut client_map: afl_shmem_t =
        {
            let mut init =
                afl_shmem{shm_str: [0; 20],
                          shm_id: 0,
                          map: 0 as *mut u8_0,
                          map_size: 0,};
            init
        };
    if llmp_new_page_shmem(&mut client_map, (*broker).llmp_client_count,
                           ((1 as libc::c_int) << 28 as libc::c_int) as
                               size_t).is_null() {
        printf(b"[D] [src/llmp.c:1518] Failed to set up shmem for new client.\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    let mut pthread: *mut pthread_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<pthread_t>() as libc::c_ulong) as
            *mut pthread_t;
    if pthread.is_null() {
        printf(b"[D] [src/llmp.c:1526] Failed to alloc pthread struct\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_shmem_deinit(&mut client_map);
        return 0 as libc::c_int != 0
    }
    let mut client: *mut llmp_broker_clientdata_t =
        llmp_broker_register_client(broker, client_map.shm_str.as_mut_ptr(),
                                    client_map.map_size);
    if client.is_null() {
        printf(b"[D] [src/llmp.c:1535] Could not register threaded client\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_shmem_deinit(&mut client_map);
        free(pthread as *mut libc::c_void);
        return 0 as libc::c_int != 0
    }
    (*client).clientloop = clientloop;
    (*client).data = data;
    (*client).pthread = pthread;
    (*client).client_type = LLMP_CLIENT_TYPE_PTHREAD;
    /* Copy the already allocated shmem to the client state */
    (*(*client).client_state).out_maps =
        afl_realloc((*(*client).client_state).out_maps as *mut libc::c_void,
                    ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong) as
            *mut afl_shmem_t;
    if (*(*client).client_state).out_maps.is_null() {
        printf(b"[D] [src/llmp.c:1550] Could not alloc mem for client map\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_shmem_deinit(&mut client_map);
        afl_shmem_deinit((*client).cur_client_map);
        free(pthread as *mut libc::c_void);
        /* "Unregister" by subtracting the client from count */
        (*broker).llmp_client_count =
            (*broker).llmp_client_count.wrapping_sub(1);
        return 0 as libc::c_int != 0
    }
    memcpy((*(*client).client_state).out_maps as *mut libc::c_void,
           &mut client_map as *mut afl_shmem_t as *const libc::c_void,
           ::std::mem::size_of::<afl_shmem_t>() as libc::c_ulong);
    (*(*client).client_state).out_map_count = 1 as libc::c_int as size_t;
    /* Each client starts with the very first map.
  They should then iterate through all maps once and work on all old messages.
  */
    (*(*client).client_state).current_broadcast_map =
        &mut *(*broker).broadcast_maps.offset(0 as libc::c_int as isize) as
            *mut afl_shmem_t;
    (*(*client).client_state).out_map_count = 1 as libc::c_int as size_t;
    printf(b"[D] [src/llmp.c:1569] Registered threaded client with id %d (loop func at %p)\x00"
               as *const u8 as *const libc::c_char,
           (*(*client).client_state).id, (*client).clientloop);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    return 1 as libc::c_int != 0;
}
/* Register a simple tcp client that will listen for new shard map clients via
 * tcp */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_register_local_server(mut broker:
                                                               *mut llmp_broker_t,
                                                           mut port:
                                                               libc::c_int)
 -> bool {
    if !llmp_broker_register_threaded_clientloop(broker,
                                                 Some(llmp_clientloop_process_server
                                                          as
                                                          unsafe extern "C" fn(_:
                                                                                   *mut llmp_client_t,
                                                                               _:
                                                                                   *mut libc::c_void)
                                                              -> ()),
                                                 port as size_t as
                                                     *mut libc::c_void) {
        printf(b"[D] [src/llmp.c:1581] Error registering new threaded client\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    return 1 as libc::c_int != 0;
}
/* Generic function to add a hook to the mem pointed to by hooks_p, using afl_realloc on the mem area, and increasing
 * hooks_count_p */
#[no_mangle]
pub unsafe extern "C" fn llmp_add_hook_generic(mut hooks_p:
                                                   *mut *mut llmp_hookdata_t,
                                               mut hooks_count_p: *mut size_t,
                                               mut new_hook_func:
                                                   *mut libc::c_void,
                                               mut new_hook_data:
                                                   *mut libc::c_void)
 -> afl_ret_t {
    let mut hooks_count: size_t = *hooks_count_p;
    let mut hooks: *mut llmp_hookdata_t =
        afl_realloc(*hooks_p as *mut libc::c_void,
                    hooks_count.wrapping_add(1 as libc::c_int as
                                                 libc::c_ulong).wrapping_mul(::std::mem::size_of::<llmp_hookdata_t>()
                                                                                 as
                                                                                 libc::c_ulong))
            as *mut llmp_hookdata_t;
    if hooks.is_null() {
        printf(b"[D] [src/llmp.c:1599] realloc for msg hooks failed\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        *hooks_p = 0 as *mut llmp_hookdata_t;
        *hooks_count_p = 0 as libc::c_int as size_t;
        return AFL_RET_ALLOC
    }
    let ref mut fresh0 = (*hooks.offset(hooks_count as isize)).func;
    *fresh0 = new_hook_func;
    let ref mut fresh1 = (*hooks.offset(hooks_count as isize)).data;
    *fresh1 = new_hook_data;
    *hooks_p = hooks;
    *hooks_count_p =
        hooks_count.wrapping_add(1 as libc::c_int as libc::c_ulong);
    return AFL_RET_SUCCESS;
}
/* Adds a hook that gets called in the client for each new outgoing page the client creates. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_add_new_out_page_hook(mut client:
                                                               *mut llmp_client_t,
                                                           mut hook:
                                                               Option<llmp_client_new_page_hook_func>,
                                                           mut data:
                                                               *mut libc::c_void)
 -> afl_ret_t {
    return llmp_add_hook_generic(&mut (*client).new_out_page_hooks,
                                 &mut (*client).new_out_page_hook_count,
                                 ::std::mem::transmute::<Option<llmp_client_new_page_hook_func>,
                                                         *mut libc::c_void>(hook),
                                 data);
}
/* Register a new forked/child client.
Client thread will be called with llmp_client_t client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
/* Client thread will be called with llmp_client_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
/* launch a specific client. This function is rarely needed - all registered clients will get launched at broker_run */
/* Kicks off all threaded clients in the brackground, using pthreads */
/* Register a simple tcp client that will listen for new shard map clients via
 tcp */
/* Adds a hook that gets called for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
/* Adds a hook that gets called in the broker for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_add_message_hook(mut broker:
                                                          *mut llmp_broker_t,
                                                      mut hook:
                                                          Option<llmp_message_hook_func>,
                                                      mut data:
                                                          *mut libc::c_void)
 -> afl_ret_t {
    return llmp_add_hook_generic(&mut (*broker).msg_hooks,
                                 &mut (*broker).msg_hook_count,
                                 ::std::mem::transmute::<Option<llmp_message_hook_func>,
                                                         *mut libc::c_void>(hook),
                                 data);
}
/* Allocate and set up the new broker instance. Afterwards, run with
 * broker_run.
 */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_init(mut broker: *mut llmp_broker_t)
 -> afl_ret_t {
    memset(broker as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<llmp_broker_t>() as libc::c_ulong);
    /* let's create some space for outgoing maps */
    (*broker).broadcast_maps =
        afl_realloc(0 as *mut libc::c_void,
                    (1 as libc::c_int as
                         libc::c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem_t>()
                                                         as libc::c_ulong)) as
            *mut afl_shmem_t;
    if (*broker).broadcast_maps.is_null() {
        printf(b"[D] [src/llmp.c:1639] Broker map realloc failed\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return AFL_RET_ALLOC
    }
    (*broker).broadcast_map_count = 1 as libc::c_int as size_t;
    (*broker).llmp_client_count = 0 as libc::c_int as size_t;
    (*broker).llmp_clients = 0 as *mut llmp_broker_clientdata_t;
    if llmp_new_page_shmem(_llmp_broker_current_broadcast_map(broker),
                           -(1 as libc::c_int) as size_t,
                           ((1 as libc::c_int) << 28 as libc::c_int) as
                               size_t).is_null() {
        printf(b"[D] [src/llmp.c:1651] Broker map init failed\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        afl_free((*broker).broadcast_maps as *mut libc::c_void);
        return AFL_RET_ALLOC
    }
    printf(b"[D] [src/llmp.c:1657] Sucess\x00" as *const u8 as
               *const libc::c_char);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    return AFL_RET_SUCCESS;
}
/* A sharedmap page, used for unidirectional data flow.
   After a new message is added, current_msg_id should be set to the messages'
   unique id. Will then be read by the connected clients. If the page is full, a
   LLMP_TAG_END_OF_PAGE_V1 packet must be placed. In case of the broker, the
   sharedmap id of the next page must be included. The connected clients will
   instead reuse the ring buffer. Each client page needs to be large enough for
   the broker to consume all messages in the given time. Only the sender should
   ever write to this, and never remove anything.
*/
/* who sends messages to this page */
/* The only variable that may be written to by the _receiver_:
  On first message receive, save_to_unmap is set to 1. This means that
  the sender can unmap this page after EOP, on exit, ...
  Using u32 for a bool as it feels more aligned. */
/* If true, client died. :( */
/* The id of the last finished message */
/* Total size of the page */
/* How much of the page we already used */
/* The largest allocated element so far */
/* The messages start here. They can be of variable size, so don't address
   * them by array. */
/* For the client: state (also used as metadata by broker) */
/* unique ID of this client */
/* the last message we received */
/* the current broadcast map to read from */
/* the last msg we sent */
/* Number of maps we're using */
/* The maps to write to */
/* Count of the hooks we'll call for each new shared map */
/* The hooks we'll call for each new shared map */
/* A convenient clientloop function that can be run threaded on llmp broker
 * startup */
/* A hook able to intercept messages arriving at the broker.
If return is false, message will not be delivered to clients.
This is synchronous, if you need long-running message handlers, register a
client instead. */
/* A hook getting called for each new page this client creates.
Map points to the new map, containing the page, data point to the data passed when set up the hook. */
/* Unknown type, no special handling needed */
/* threaded client */
/* child process */
/* foreign process, with shared local shmap */
/* For the broker, internal: to keep track of the client */
/* client type */
/* further infos about this client */
/* The client map we're currently reading from */
  /* We can't use the one from client_state for threaded clients
  as they share the heap with us... */
/* The last message we/the broker received for this client. */
/* pthread associated to this client, if we have a threaded client */
/* process ID, if the client is a process */
/* the client loop function */
/* the engine */
/* Additional data for this client loop */
/* state of the main broker. Mostly internal stuff. */
/* Get a message buf as type if size matches (larger than, due to align),
else NULL */
/* Get a message as type if tag matches, else NULL */
/* Gets the llmp page struct from this shmem map */
/* If a msg is contained in the current page */
/* Creates a new client process that will connect to the given port */
/* Creates a new, unconnected, client state */
/* Destroys the given cient state */
/* A client receives a broadcast message. Returns null if no message is
 * availiable */
/* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
/* Will return a ptr to the next msg buf, potentially mapping a new page automatically, if needed.
Never call alloc_next multiple times without either sending or cancelling the last allocated message for this page!
There can only ever be up to one message allocated per page at each given time. */
/* Cancels a msg previously allocated by alloc_next.
You can now allocate a new buffer on this page using alloc_next.
Don't write to the msg anymore, and don't send this message! */
/* Cancel send of the next message, this allows us to allocate a new message without sending this one. */
/* Commits a msg to the client's out buf. After this, don't  write to this msg anymore! */
/* Adds a hook that gets called in the client for each new outgoing page the client creates (after start or EOP). */
/* A simple client that, on connect, reads the new client's shmap str and writes
 the broker's initial map str */
/* Allocate and set up the new broker instance. Afterwards, run with broker_run. */
/* Clean up the broker instance */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_deinit(mut broker: *mut llmp_broker_t) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*broker).broadcast_map_count {
        afl_shmem_deinit(&mut *(*broker).broadcast_maps.offset(i as isize));
        i = i.wrapping_add(1)
    }
    i = 0 as libc::c_int as size_t;
    while i < (*broker).llmp_client_count {
        afl_shmem_deinit((*(*broker).llmp_clients.offset(i as
                                                             isize)).cur_client_map);
        free((*(*broker).llmp_clients.offset(i as isize)).cur_client_map as
                 *mut libc::c_void);
        i = i.wrapping_add(1)
        // TODO: Properly clean up the client
    }
    afl_free((*broker).broadcast_maps as *mut libc::c_void);
    (*broker).broadcast_map_count = 0 as libc::c_int as size_t;
    afl_free((*broker).llmp_clients as *mut libc::c_void);
    (*broker).llmp_client_count = 0 as libc::c_int as size_t;
}
