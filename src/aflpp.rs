use ::libc;
use ::c2rust_asm_casts;
use c2rust_asm_casts::AsmCastTrait;
extern "C" {
    #[no_mangle]
    fn select(__nfds: libc::c_int, __readfds: *mut fd_set,
              __writefds: *mut fd_set, __exceptfds: *mut fd_set,
              __timeout: *mut timeval) -> libc::c_int;
    #[no_mangle]
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn rand() -> libc::c_int;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn dup2(__fd: libc::c_int, __fd2: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn execv(__path: *const libc::c_char, __argv: *const *mut libc::c_char)
     -> libc::c_int;
    #[no_mangle]
    fn setsid() -> __pid_t;
    #[no_mangle]
    fn fork() -> __pid_t;
    #[no_mangle]
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    static mut stderr: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn sprintf(_: *mut libc::c_char, _: *const libc::c_char, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn afl_observer_deinit(_: *mut afl_observer_t);
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: __time_t,
    pub tv_usec: __suseconds_t,
}
pub type __fd_mask = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fd_set {
    pub __fds_bits: [__fd_mask; 16],
}
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
/* Extended forkserver option values */
/* Reporting errors */
/* Reporting options */
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
pub type u64_0 = libc::c_ulonglong;
pub type s32 = int32_t;
pub type s64 = int64_t;
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
/* This file contains commonly used functionality for libafl */
// We're declaring a few structs here which have an interdependency between them
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
/* Tag is the (unique) tag of a message.
  It should be unique per application and version */
/* the sender's id */
/* unique id for this msg */
/* the length of the payload, as requested by the caller */
/* the actual length of the payload, including padding to the next msg */
/* the content (syntax needs c99) */
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
/* unique ID of this client */
/* the last message we received */
/* the current broadcast map to read from */
/* the last msg we sent */
/* Number of maps we're using */
/* The maps to write to */
/* Count of the hooks we'll call for each new shared map */
/* The hooks we'll call for each new shared map */
// A generic sharememory region to be used by any functions (queues or feedbacks
// too.)
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
/* Serialized map id */
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
// Inheritence from base queue
// "constructor" for the above feedback queue
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_executor {
    pub observors: *mut *mut afl_observer_t,
    pub observors_count: u32_0,
    pub current_input: *mut afl_input_t,
    pub funcs: afl_executor_funcs,
}
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
pub type afl_observer_t = afl_observer;
// vtable for the observation channel
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
This is the generic interface implementation for the queue and queue entries.
We've tried to keep it generic and yet including, but if you want to extend the
queue/entry, simply "inherit" this struct by including it in your custom struct
and keeping it as the first member of your struct.
*/
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
/*TODO: Still need to add a base implementation for this.*/
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
pub struct afl_forkserver {
    pub base: afl_executor_t,
    pub trace_bits: *mut u8_0,
    pub use_stdin: u8_0,
    pub fsrv_pid: s32,
    pub child_pid: s32,
    pub child_status: s32,
    pub out_dir_fd: s32,
    pub dev_null_fd: s32,
    pub out_fd: s32,
    pub fsrv_ctl_fd: s32,
    pub fsrv_st_fd: s32,
    pub exec_tmout: u32_0,
    pub map_size: u32_0,
    pub total_execs: u64_0,
    pub out_file: *mut libc::c_char,
    pub target_path: *mut libc::c_char,
    pub target_args: *mut *mut libc::c_char,
    pub last_run_timed_out: u32_0,
    pub last_run_time: u32_0,
    pub last_kill_signal: u8_0,
}
pub type afl_forkserver_t = afl_forkserver;
pub type harness_function_type
    =
    Option<unsafe extern "C" fn(_: *mut afl_executor_t, _: *mut u8_0,
                                _: size_t) -> afl_exit_t>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_memory_executor {
    pub base: afl_executor_t,
    pub harness: harness_function_type,
    pub argv: *mut *mut libc::c_char,
    pub argc: libc::c_int,
    pub stage: *mut afl_stage_t,
    pub global_queue: *mut afl_queue_global_t,
}
pub type in_memory_executor_t = in_memory_executor;
/* Random number counter*/
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
/* This function uses select calls to wait on a child process for given
 * timeout_ms milliseconds and kills it if it doesn't terminate by that time */
#[inline]
unsafe extern "C" fn afl_read_s32_timed(mut fd: s32, mut buf: *mut s32,
                                        mut timeout_ms: u32_0) -> u32_0 {
    let mut readfds: fd_set = fd_set{__fds_bits: [0; 16],};
    let mut __d0: libc::c_int = 0;
    let mut __d1: libc::c_int = 0;
    let fresh0 = &mut __d0;
    let fresh1;
    let fresh2 = &mut __d1;
    let fresh3;
    let fresh4 =
        (::std::mem::size_of::<fd_set>() as
             libc::c_ulong).wrapping_div(::std::mem::size_of::<__fd_mask>() as
                                             libc::c_ulong);
    let fresh5 =
        &mut *readfds.__fds_bits.as_mut_ptr().offset(0 as libc::c_int as
                                                         isize) as
            *mut __fd_mask;
    asm!("cld; rep; stosq" : "={cx}" (fresh1), "={di}" (fresh3) : "{ax}"
         (0 as libc::c_int), "0"
         (c2rust_asm_casts::AsmCast::cast_in(fresh0, fresh4)), "1"
         (c2rust_asm_casts::AsmCast::cast_in(fresh2, fresh5)) : "memory" :
         "volatile");
    c2rust_asm_casts::AsmCast::cast_out(fresh0, fresh4, fresh1);
    c2rust_asm_casts::AsmCast::cast_out(fresh2, fresh5, fresh3);
    readfds.__fds_bits[(fd /
                            (8 as libc::c_int *
                                 ::std::mem::size_of::<__fd_mask>() as
                                     libc::c_ulong as libc::c_int)) as usize]
        |=
        ((1 as libc::c_ulong) <<
             fd %
                 (8 as libc::c_int *
                      ::std::mem::size_of::<__fd_mask>() as libc::c_ulong as
                          libc::c_int)) as __fd_mask;
    let mut timeout: timeval = timeval{tv_sec: 0, tv_usec: 0,};
    let mut sret: libc::c_int = 0;
    let mut len_read: ssize_t = 0;
    timeout.tv_sec =
        timeout_ms.wrapping_div(1000 as libc::c_int as libc::c_uint) as
            __time_t;
    timeout.tv_usec =
        timeout_ms.wrapping_rem(1000 as libc::c_int as
                                    libc::c_uint).wrapping_mul(1000 as
                                                                   libc::c_int
                                                                   as
                                                                   libc::c_uint)
            as __suseconds_t;
    loop 
         /* set exceptfds as well to return when a child exited/closed the pipe. */
         {
        sret =
            select(fd + 1 as libc::c_int, &mut readfds, 0 as *mut fd_set,
                   0 as *mut fd_set, &mut timeout);
        if sret > 0 as libc::c_int {
            's_96:
                {
                    loop  {
                        len_read =
                            read(fd, buf as *mut u8_0 as *mut libc::c_void,
                                 4 as libc::c_int as size_t);
                        if len_read == 4 as libc::c_int as libc::c_long {
                            // for speed we put this first
                            let mut exec_ms: u32_0 =
                                ({
                                     let mut _a: u32_0 = timeout_ms;
                                     let mut _b: libc::c_ulonglong =
                                         (timeout_ms as
                                              u64_0).wrapping_sub((timeout.tv_sec
                                                                       *
                                                                       1000 as
                                                                           libc::c_int
                                                                           as
                                                                           libc::c_long
                                                                       +
                                                                       timeout.tv_usec
                                                                           /
                                                                           1000
                                                                               as
                                                                               libc::c_int
                                                                               as
                                                                               libc::c_long)
                                                                      as
                                                                      libc::c_ulonglong);
                                     if (_a as libc::c_ulonglong) < _b {
                                         _a as libc::c_ulonglong
                                     } else { _b }
                                 }) as u32_0;
                            // ensure to report 1 ms has passed (0 is an error)
                            return if exec_ms >
                                          0 as libc::c_int as libc::c_uint {
                                       exec_ms
                                   } else { 1 as libc::c_int as libc::c_uint }
                        } else {
                            if len_read == -(1 as libc::c_int) as libc::c_long
                                   && *__errno_location() == 4 as libc::c_int
                               {
                                continue ;
                            }
                            if len_read < 4 as libc::c_int as libc::c_long {
                                return 0 as libc::c_int as u32_0
                            }
                            break 's_96 ;
                        }
                    }
                }
            break ;
        } else if sret == 0 {
            *buf = -(1 as libc::c_int);
            return timeout_ms.wrapping_add(1 as libc::c_int as libc::c_uint)
        } else {
            if !(sret < 0 as libc::c_int) { break ; }
            if *__errno_location() == 4 as libc::c_int { continue ; }
            *buf = -(1 as libc::c_int);
            return 0 as libc::c_int as u32_0
        }
    }
    return 0 as libc::c_int as u32_0;
    // not reached
}
/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the actual code for the library framework.

 */
#[no_mangle]
pub unsafe extern "C" fn afl_executor_init(mut executor: *mut afl_executor_t)
 -> afl_ret_t {
    memset(executor as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<afl_executor_t>() as libc::c_ulong);
    (*executor).current_input = 0 as *mut afl_input_t;
    (*executor).observors = 0 as *mut *mut afl_observer_t;
    (*executor).observors_count = 0 as libc::c_int as u32_0;
    // Default implementations of the functions
    (*executor).funcs.init_cb = None;
    (*executor).funcs.destroy_cb = None;
    (*executor).funcs.place_input_cb = None;
    (*executor).funcs.run_target_cb = None;
    (*executor).funcs.observer_add =
        Some(afl_executor_add_observer as
                 unsafe extern "C" fn(_: *mut afl_executor_t,
                                      _: *mut afl_observer_t) -> afl_ret_t);
    (*executor).funcs.observers_reset =
        Some(afl_observers_reset as
                 unsafe extern "C" fn(_: *mut afl_executor_t) -> ());
    return AFL_RET_SUCCESS;
}
// Default implementations for executor vtable
#[no_mangle]
pub unsafe extern "C" fn afl_executor_deinit(mut executor:
                                                 *mut afl_executor_t) {
    let mut i: size_t = 0;
    (*executor).current_input = 0 as *mut afl_input_t;
    i = 0 as libc::c_int as size_t;
    while i < (*executor).observors_count as libc::c_ulong {
        afl_observer_deinit(*(*executor).observors.offset(i as isize));
        i = i.wrapping_add(1)
    }
    afl_free((*executor).observors as *mut libc::c_void);
    (*executor).observors = 0 as *mut *mut afl_observer_t;
    (*executor).observors_count = 0 as libc::c_int as u32_0;
}
#[no_mangle]
pub unsafe extern "C" fn afl_executor_add_observer(mut executor:
                                                       *mut afl_executor_t,
                                                   mut obs_channel:
                                                       *mut afl_observer_t)
 -> afl_ret_t {
    (*executor).observors_count = (*executor).observors_count.wrapping_add(1);
    (*executor).observors =
        afl_realloc((*executor).observors as *mut libc::c_void,
                    ((*executor).observors_count as
                         libc::c_ulong).wrapping_mul(::std::mem::size_of::<*mut afl_observer_t>()
                                                         as libc::c_ulong)) as
            *mut *mut afl_observer_t;
    if (*executor).observors.is_null() { return AFL_RET_ALLOC }
    let ref mut fresh6 =
        *(*executor).observors.offset((*executor).observors_count.wrapping_sub(1
                                                                                   as
                                                                                   libc::c_int
                                                                                   as
                                                                                   libc::c_uint)
                                          as isize);
    *fresh6 = obs_channel;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_executor_get_current_input(mut executor:
                                                            *mut afl_executor_t)
 -> *mut afl_input_t {
    return (*executor).current_input;
}
#[no_mangle]
pub unsafe extern "C" fn afl_observers_reset(mut executor:
                                                 *mut afl_executor_t) {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*executor).observors_count as libc::c_ulong {
        let mut obs_channel: *mut afl_observer_t =
            *(*executor).observors.offset(i as isize);
        if (*obs_channel).funcs.reset.is_some() {
            (*obs_channel).funcs.reset.expect("non-null function pointer")(obs_channel);
        }
        i = i.wrapping_add(1)
    };
}
/* Function to simple initialize the forkserver */
#[no_mangle]
pub unsafe extern "C" fn fsrv_init(mut target_path: *mut libc::c_char,
                                   mut target_args: *mut *mut libc::c_char)
 -> *mut afl_forkserver_t {
    let mut fsrv: *mut afl_forkserver_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_forkserver_t>() as libc::c_ulong) as
            *mut afl_forkserver_t;
    if fsrv.is_null() { return 0 as *mut afl_forkserver_t }
    if afl_executor_init(&mut (*fsrv).base) as u64 != 0 {
        free(fsrv as *mut libc::c_void);
        return 0 as *mut afl_forkserver_t
    }
    /* defining standard functions for the forkserver vtable */
    (*fsrv).base.funcs.init_cb =
        Some(fsrv_start as
                 unsafe extern "C" fn(_: *mut afl_executor_t)
                     -> afl_ret_t); // Replace @@ with the output file name
    (*fsrv).base.funcs.place_input_cb =
        Some(fsrv_place_input as
                 unsafe extern "C" fn(_: *mut afl_executor_t,
                                      _: *mut afl_input_t) -> u8_0);
    (*fsrv).base.funcs.run_target_cb =
        Some(fsrv_run_target as
                 unsafe extern "C" fn(_: *mut afl_executor_t) -> afl_exit_t);
    (*fsrv).use_stdin = 1 as libc::c_int as u8_0;
    (*fsrv).target_path = target_path;
    (*fsrv).target_args = target_args;
    (*fsrv).out_file =
        calloc(1 as libc::c_int as libc::c_ulong,
               50 as libc::c_int as libc::c_ulong) as *mut libc::c_char;
    snprintf((*fsrv).out_file, 50 as libc::c_int as libc::c_ulong,
             b"out-%d\x00" as *const u8 as *const libc::c_char, rand());
    let mut target_args_copy: *mut *mut libc::c_char = target_args;
    while !(*target_args_copy).is_null() {
        if strcmp(*target_args_copy,
                  b"@@\x00" as *const u8 as *const libc::c_char) == 0 {
            (*fsrv).use_stdin = 0 as libc::c_int as u8_0;
            *target_args_copy = (*fsrv).out_file;
            break ;
        } else { target_args_copy = target_args_copy.offset(1) }
    }
    /* FD for the stdin of the child process */
    if (*fsrv).use_stdin != 0 {
        if (*fsrv).out_file.is_null() {
            (*fsrv).out_fd = -(1 as libc::c_int)
        } else {
            (*fsrv).out_fd =
                open((*fsrv).out_file,
                     0o1 as libc::c_int | 0o100 as libc::c_int,
                     0o600 as libc::c_int);
            if (*fsrv).out_fd == 0 {
                afl_executor_deinit(&mut (*fsrv).base);
                free(fsrv as *mut libc::c_void);
                return 0 as *mut afl_forkserver_t
            }
        }
    }
    (*fsrv).out_dir_fd = -(1 as libc::c_int);
    (*fsrv).dev_null_fd =
        open(b"/dev/null\x00" as *const u8 as *const libc::c_char,
             0o1 as libc::c_int);
    if (*fsrv).dev_null_fd == 0 {
        close((*fsrv).out_fd);
        afl_executor_deinit(&mut (*fsrv).base);
        free(fsrv as *mut libc::c_void);
        return 0 as *mut afl_forkserver_t
    }
    /* exec related stuff */
    (*fsrv).child_pid = -(1 as libc::c_int); /* Default exec time in ms */
    (*fsrv).exec_tmout = 0 as libc::c_int as u32_0;
    return fsrv;
}
/* This function starts up the forkserver for further process requests */
#[no_mangle]
pub unsafe extern "C" fn fsrv_start(mut fsrv_executor: *mut afl_executor_t)
 -> afl_ret_t {
    let mut fsrv: *mut afl_forkserver_t =
        fsrv_executor as *mut afl_forkserver_t;
    let mut st_pipe: [libc::c_int; 2] = [0; 2];
    let mut ctl_pipe: [libc::c_int; 2] = [0; 2];
    let mut status: s32 = 0;
    let mut rlen: s32 = 0;
    printf(b"\x1b[1;94m[*] \x1b[0mSpinning up the fork server...\x00" as
               *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    if pipe(st_pipe.as_mut_ptr()) != 0 || pipe(ctl_pipe.as_mut_ptr()) != 0 {
        return AFL_RET_ERRNO
    }
    (*fsrv).last_run_timed_out = 0 as libc::c_int as u32_0;
    (*fsrv).fsrv_pid = fork();
    if (*fsrv).fsrv_pid < 0 as libc::c_int { return AFL_RET_ERRNO }
    if (*fsrv).fsrv_pid == 0 {
        /* CHILD PROCESS */
        setsid();
        if (*fsrv).use_stdin != 0 {
            (*fsrv).out_fd =
                open((*fsrv).out_file,
                     0 as libc::c_int | 0o100 as libc::c_int,
                     0o600 as libc::c_int);
            if (*fsrv).out_fd == 0 {
                fflush(stdout);
                printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mCould not open outfile in child\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00"
                           as *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 11],
                                                 &[libc::c_char; 11]>(b"fsrv_start\x00")).as_ptr(),
                       b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                       206 as libc::c_int);
                printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as
                           *const u8 as *const libc::c_char,
                       strerror(*__errno_location()));
                exit(1 as libc::c_int);
            }
            dup2((*fsrv).out_fd, 0 as libc::c_int);
            close((*fsrv).out_fd);
        }
        dup2((*fsrv).dev_null_fd, 1 as libc::c_int);
        dup2((*fsrv).dev_null_fd, 2 as libc::c_int);
        /* Set up control and status pipes, close the unneeded original fds. */
        if dup2(ctl_pipe[0 as libc::c_int as usize], 198 as libc::c_int) <
               0 as libc::c_int {
            fflush(stdout);
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mdup2() failed\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 11],
                                             &[libc::c_char; 11]>(b"fsrv_start\x00")).as_ptr(),
                   b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                   218 as libc::c_int);
            printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as
                       *const u8 as *const libc::c_char,
                   strerror(*__errno_location()));
            exit(1 as libc::c_int);
        }
        if dup2(st_pipe[1 as libc::c_int as usize],
                198 as libc::c_int + 1 as libc::c_int) < 0 as libc::c_int {
            fflush(stdout);
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mdup2() failed\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 11],
                                             &[libc::c_char; 11]>(b"fsrv_start\x00")).as_ptr(),
                   b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                   219 as libc::c_int);
            printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as
                       *const u8 as *const libc::c_char,
                   strerror(*__errno_location()));
            exit(1 as libc::c_int);
        }
        close(ctl_pipe[0 as libc::c_int as usize]);
        close(ctl_pipe[1 as libc::c_int as usize]);
        close(st_pipe[0 as libc::c_int as usize]);
        close(st_pipe[1 as libc::c_int as usize]);
        execv((*fsrv).target_path,
              (*fsrv).target_args as *const *mut libc::c_char);
        /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */
        (*fsrv).trace_bits = 0xdeadbeef as libc::c_uint as *mut u8_0;
        fprintf(stderr,
                b"Error: execv to target failed\n\x00" as *const u8 as
                    *const libc::c_char);
        exit(0 as libc::c_int);
    }
    /* PARENT PROCESS */
    let mut pid_buf: [libc::c_char; 16] = [0; 16];
    sprintf(pid_buf.as_mut_ptr(),
            b"%d\x00" as *const u8 as *const libc::c_char, (*fsrv).fsrv_pid);
    /* Close the unneeded endpoints. */
    close(ctl_pipe[0 as libc::c_int as usize]);
    close(st_pipe[1 as libc::c_int as usize]);
    (*fsrv).fsrv_ctl_fd = ctl_pipe[1 as libc::c_int as usize];
    (*fsrv).fsrv_st_fd = st_pipe[0 as libc::c_int as usize];
    /* Wait for the fork server to come up, but don't wait too long. */
    rlen = 0 as libc::c_int;
    if (*fsrv).exec_tmout != 0 {
        let mut time_ms: u32_0 =
            afl_read_s32_timed((*fsrv).fsrv_st_fd, &mut status,
                               (*fsrv).exec_tmout.wrapping_mul(10 as
                                                                   libc::c_int
                                                                   as
                                                                   libc::c_uint));
        if time_ms == 0 {
            kill((*fsrv).fsrv_pid, 9 as libc::c_int);
        } else if time_ms >
                      (*fsrv).exec_tmout.wrapping_mul(10 as libc::c_int as
                                                          libc::c_uint) {
            (*fsrv).last_run_timed_out = 1 as libc::c_int as u32_0;
            kill((*fsrv).fsrv_pid, 9 as libc::c_int);
        } else { rlen = 4 as libc::c_int }
    } else {
        rlen =
            read((*fsrv).fsrv_st_fd,
                 &mut status as *mut s32 as *mut libc::c_void,
                 4 as libc::c_int as size_t) as s32
    }
    /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */
    if rlen == 4 as libc::c_int {
        printf(b"\x1b[1;92m[+] \x1b[0mAll right - fork server is up.\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        return AFL_RET_SUCCESS
    }
    if (*fsrv).trace_bits == 0xdeadbeef as libc::c_uint as *mut u8_0 {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mUnable to execute target application (\'%s\')\x00"
                   as *const u8 as *const libc::c_char,
               *(*fsrv).target_args.offset(0 as libc::c_int as isize));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        return AFL_RET_EXEC_ERROR
    }
    printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mFork server handshake failed\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    return AFL_RET_BROKEN_TARGET;
}
/* Places input in the executor for the target */
#[no_mangle]
pub unsafe extern "C" fn fsrv_place_input(mut fsrv_executor:
                                              *mut afl_executor_t,
                                          mut input: *mut afl_input_t)
 -> u8_0 {
    let mut fsrv: *mut afl_forkserver_t =
        fsrv_executor as *mut afl_forkserver_t;
    if (*fsrv).use_stdin == 0 {
        (*fsrv).out_fd =
            open((*fsrv).out_file,
                 0o2 as libc::c_int | 0o100 as libc::c_int |
                     0o200 as libc::c_int, 0o600 as libc::c_int)
    }
    let mut write_len: ssize_t =
        write((*fsrv).out_fd, (*input).bytes as *const libc::c_void,
              (*input).len);
    if write_len < 0 as libc::c_int as libc::c_long ||
           write_len as size_t != (*input).len {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mShort Write\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 17],
                                         &[libc::c_char; 17]>(b"fsrv_place_input\x00")).as_ptr(),
               b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
               308 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*fsrv).base.current_input = input;
    if (*fsrv).use_stdin == 0 { close((*fsrv).out_fd); }
    return write_len as u8_0;
}
/* Execute target application. Return status
   information.*/
#[no_mangle]
pub unsafe extern "C" fn fsrv_run_target(mut fsrv_executor:
                                             *mut afl_executor_t)
 -> afl_exit_t {
    let mut fsrv: *mut afl_forkserver_t =
        fsrv_executor as *mut afl_forkserver_t;
    let mut res: s32 = 0;
    let mut exec_ms: u32_0 = 0;
    let mut write_value: u32_0 = (*fsrv).last_run_timed_out;
    /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */
    // memset(fsrv->trace_bits, 0, fsrv->map_size);
    asm!("" : : : "memory" : "volatile");
    /* we have the fork server (or faux server) up and running
  First, tell it if the previous run timed out. */
    res =
        write((*fsrv).fsrv_ctl_fd,
              &mut write_value as *mut u32_0 as *const libc::c_void,
              4 as libc::c_int as size_t) as s32;
    if res != 4 as libc::c_int {
        if res < 0 as libc::c_int {
            fflush(stdout);
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mUnable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 16],
                                             &[libc::c_char; 16]>(b"fsrv_run_target\x00")).as_ptr(),
                   b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                   341 as libc::c_int);
            printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as
                       *const u8 as *const libc::c_char,
                   strerror(*__errno_location()));
            exit(1 as libc::c_int);
        } else {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mUnable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 16],
                                             &[libc::c_char; 16]>(b"fsrv_run_target\x00")).as_ptr(),
                   b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                   341 as libc::c_int);
            exit(1 as libc::c_int);
        }
    }
    (*fsrv).last_run_timed_out = 0 as libc::c_int as u32_0;
    res =
        read((*fsrv).fsrv_st_fd,
             &mut (*fsrv).child_pid as *mut s32 as *mut libc::c_void,
             4 as libc::c_int as size_t) as s32;
    if res != 4 as libc::c_int {
        if res < 0 as libc::c_int {
            fflush(stdout);
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-]  SYSTEM ERROR : \x1b[0mUnable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n    Stop location : \x1b[0m%s(), %s:%u\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 16],
                                             &[libc::c_char; 16]>(b"fsrv_run_target\x00")).as_ptr(),
                   b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                   349 as libc::c_int);
            printf(b"\x1b[1;91m       OS message : \x1b[0m%s\n\x00" as
                       *const u8 as *const libc::c_char,
                   strerror(*__errno_location()));
            exit(1 as libc::c_int);
        } else {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mUnable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 16],
                                             &[libc::c_char; 16]>(b"fsrv_run_target\x00")).as_ptr(),
                   b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
                   349 as libc::c_int);
            exit(1 as libc::c_int);
        }
    }
    if (*fsrv).child_pid <= 0 as libc::c_int {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mFork server is misbehaving (OOM?)\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 16],
                                         &[libc::c_char; 16]>(b"fsrv_run_target\x00")).as_ptr(),
               b"src/aflpp.c\x00" as *const u8 as *const libc::c_char,
               353 as libc::c_int);
        exit(1 as libc::c_int);
    }
    exec_ms =
        afl_read_s32_timed((*fsrv).fsrv_st_fd, &mut (*fsrv).child_status,
                           (*fsrv).exec_tmout);
    if exec_ms > (*fsrv).exec_tmout {
        /* If there was no response from forkserver after timeout seconds,
    we kill the child. The forkserver should inform us afterwards */
        kill((*fsrv).child_pid, 9 as libc::c_int);
        (*fsrv).last_run_timed_out = 1 as libc::c_int as u32_0;
        if read((*fsrv).fsrv_st_fd,
                &mut (*fsrv).child_status as *mut s32 as *mut libc::c_void,
                4 as libc::c_int as size_t) < 4 as libc::c_int as libc::c_long
           {
            exec_ms = 0 as libc::c_int as u32_0
        }
    }
    (exec_ms) == 0;
    if !((*fsrv).child_status & 0xff as libc::c_int == 0x7f as libc::c_int) {
        (*fsrv).child_pid = 0 as libc::c_int
    }
    (*fsrv).total_execs = (*fsrv).total_execs.wrapping_add(1);
    if (*fsrv).use_stdin == 0 { unlink((*fsrv).out_file); }
    /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */
    asm!("" : : : "memory" : "volatile");
    /* Report outcome to caller. */
    if (((*fsrv).child_status & 0x7f as libc::c_int) + 1 as libc::c_int) as
           libc::c_schar as libc::c_int >> 1 as libc::c_int > 0 as libc::c_int
       {
        (*fsrv).last_kill_signal =
            ((*fsrv).child_status & 0x7f as libc::c_int) as u8_0;
        if (*fsrv).last_run_timed_out != 0 &&
               (*fsrv).last_kill_signal as libc::c_int == 9 as libc::c_int {
            return AFL_EXIT_TIMEOUT
        }
        return AFL_EXIT_CRASH
    }
    return AFL_EXIT_OK;
}
/* An in-mem executor we have */
#[no_mangle]
pub unsafe extern "C" fn in_memory_executor_init(mut in_memory_executor:
                                                     *mut in_memory_executor_t,
                                                 mut harness:
                                                     harness_function_type) {
    afl_executor_init(&mut (*in_memory_executor).base);
    (*in_memory_executor).harness = harness;
    (*in_memory_executor).argv = 0 as *mut *mut libc::c_char;
    (*in_memory_executor).argc = 0 as libc::c_int;
    (*in_memory_executor).base.funcs.run_target_cb =
        Some(in_memory_run_target as
                 unsafe extern "C" fn(_: *mut afl_executor_t) -> afl_exit_t);
    (*in_memory_executor).base.funcs.place_input_cb =
        Some(in_mem_executor_place_input as
                 unsafe extern "C" fn(_: *mut afl_executor_t,
                                      _: *mut afl_input_t) -> u8_0);
}
#[no_mangle]
pub unsafe extern "C" fn in_memory_executor_deinit(mut in_memory_executor:
                                                       *mut in_memory_executor_t) {
    afl_executor_deinit(&mut (*in_memory_executor).base);
    (*in_memory_executor).harness = None;
    (*in_memory_executor).argv = 0 as *mut *mut libc::c_char;
    (*in_memory_executor).argc = 0 as libc::c_int;
    (*in_memory_executor).base.funcs.run_target_cb =
        Some(in_memory_run_target as
                 unsafe extern "C" fn(_: *mut afl_executor_t) -> afl_exit_t);
    (*in_memory_executor).base.funcs.place_input_cb =
        Some(in_mem_executor_place_input as
                 unsafe extern "C" fn(_: *mut afl_executor_t,
                                      _: *mut afl_input_t) -> u8_0);
}
#[no_mangle]
pub unsafe extern "C" fn in_mem_executor_place_input(mut executor:
                                                         *mut afl_executor_t,
                                                     mut input:
                                                         *mut afl_input_t)
 -> u8_0 {
    (*executor).current_input = input;
    return 0 as libc::c_int as u8_0;
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
// can be NULL
// can be NULL
// Similar to afl_fsrv_run_target we have in afl
// similar to the write_to_testcase function in afl.
// Add an observtion channel to the list
// Getter function for the current input
// Reset the observation channels
// This is like the generic vtable for the executor.
// This will be swapped for the observation channel once its ready
// Holds current input for the executor
// afl executor_ops;
// Function used to create an executor, we alloc the memory ourselves and
// initialize the executor
/* Forkserver executor */
/* executer struct to inherit from */
/* SHM with instrumentation bitmap  */
/* use stdin for sending data       */
/* PID of the fork server           */
/* PID of the fuzzed program        */
/* waitpid result for the child     */
/* FD of the lock file              */
/* Persistent fd for fsrv->out_file */
/* Fork server control pipe (write) */
/* Fork server status pipe (read)   */
/* Configurable exec timeout (ms)   */
/* map size used by the target      */
/* How often run_target was called  */
/* File to fuzz, if any             */
/* Path of the target               */
/* Traced process timed out?        */
/* Time this exec took to execute   */
/* Signal that killed the child     */
/* Functions related to the forkserver defined above */
/* In-memory executor */
/* Function ptr for the harness */
// These are to support the libfuzzer harnesses
// To support libfuzzer harnesses
#[no_mangle]
pub unsafe extern "C" fn in_memory_run_target(mut executor:
                                                  *mut afl_executor_t)
 -> afl_exit_t {
    let mut in_memory_executor: *mut in_memory_executor_t =
        executor as *mut in_memory_executor_t;
    let mut input: *mut afl_input_t =
        (*in_memory_executor).base.current_input;
    let mut data: *mut u8_0 =
        if (*input).funcs.serialize.is_some() {
            (*input).funcs.serialize.expect("non-null function pointer")(input)
        } else { (*input).bytes };
    let mut run_result: afl_exit_t =
        (*in_memory_executor).harness.expect("non-null function pointer")(&mut (*in_memory_executor).base,
                                                                          data,
                                                                          (*input).len);
    return run_result;
}
