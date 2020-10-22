use ::libc;
extern "C" {
    pub type afl_executor;
    #[no_mangle]
    fn mkdir(__path: *const libc::c_char, __mode: __mode_t) -> libc::c_int;
    #[no_mangle]
    fn __xstat(__ver: libc::c_int, __filename: *const libc::c_char,
               __stat_buf: *mut stat) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
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
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char)
     -> *mut libc::c_char;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn snprintf(_: *mut libc::c_char, _: libc::c_ulong,
                _: *const libc::c_char, _: ...) -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
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
pub type size_t = libc::c_ulong;
pub type ssize_t = __ssize_t;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
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
pub type u32_0 = uint32_t;
/* Extended forkserver option values */
/* Reporting errors */
/* Reporting options */
// FS_OPT_MAX_MAPSIZE is 8388608 = 0x800000 = 2^23 = 1 << 22
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_fuzz_one {
    pub engine: *mut afl_engine_t,
    pub stages: *mut *mut afl_stage_t,
    pub stages_count: size_t,
    pub funcs: afl_fuzz_one_funcs,
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
pub type afl_input_t = afl_input;
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
/* Random number counter*/
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
pub type XXH64_hash_t = uint64_t;
pub type xxh_u64 = XXH64_hash_t;
pub type XXH_alignment = libc::c_uint;
pub const XXH_unaligned: XXH_alignment = 1;
pub const XXH_aligned: XXH_alignment = 0;
pub type xxh_u8 = uint8_t;
pub type xxh_u32 = XXH32_hash_t;
pub type XXH32_hash_t = uint32_t;
#[inline]
unsafe extern "C" fn stat(mut __path: *const libc::c_char,
                          mut __statbuf: *mut stat) -> libc::c_int {
    return __xstat(1 as libc::c_int, __path, __statbuf);
}
#[inline]
unsafe extern "C" fn afl_entry_delete(mut afl_entry: *mut afl_entry_t) {
    afl_entry_deinit(afl_entry);
    free(afl_entry as *mut libc::c_void);
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
#[inline]
unsafe extern "C" fn afl_rand_rotl(x: u64_0, mut k: libc::c_int) -> u64_0 {
    return x << k | x >> 64 as libc::c_int - k;
}
#[inline]
unsafe extern "C" fn afl_rand_next(mut rnd: *mut afl_rand_t) -> u64_0 {
    let result: uint64_t =
        afl_rand_rotl((*rnd).rand_seed[0 as libc::c_int as
                                           usize].wrapping_add((*rnd).rand_seed[3
                                                                                    as
                                                                                    libc::c_int
                                                                                    as
                                                                                    usize]),
                      23 as
                          libc::c_int).wrapping_add((*rnd).rand_seed[0 as
                                                                         libc::c_int
                                                                         as
                                                                         usize])
            as uint64_t;
    let t: uint64_t =
        ((*rnd).rand_seed[1 as libc::c_int as usize] << 17 as libc::c_int) as
            uint64_t;
    (*rnd).rand_seed[2 as libc::c_int as usize] ^=
        (*rnd).rand_seed[0 as libc::c_int as usize];
    (*rnd).rand_seed[3 as libc::c_int as usize] ^=
        (*rnd).rand_seed[1 as libc::c_int as usize];
    (*rnd).rand_seed[1 as libc::c_int as usize] ^=
        (*rnd).rand_seed[2 as libc::c_int as usize];
    (*rnd).rand_seed[0 as libc::c_int as usize] ^=
        (*rnd).rand_seed[3 as libc::c_int as usize];
    (*rnd).rand_seed[2 as libc::c_int as usize] ^= t as libc::c_ulonglong;
    (*rnd).rand_seed[3 as libc::c_int as usize] =
        afl_rand_rotl((*rnd).rand_seed[3 as libc::c_int as usize],
                      45 as libc::c_int);
    return result as u64_0;
}
#[inline]
unsafe extern "C" fn afl_rand_below(mut rnd: *mut afl_rand_t,
                                    mut limit: u64_0) -> u64_0 {
    if limit <= 1 as libc::c_int as libc::c_ulonglong {
        return 0 as libc::c_int as u64_0
    }
    let fresh0 = (*rnd).rand_cnt;
    (*rnd).rand_cnt = (*rnd).rand_cnt.wrapping_sub(1);
    if fresh0 == 0 && !(*rnd).fixed_seed {
        let mut read_len: libc::c_int =
            read((*rnd).dev_urandom_fd,
                 &mut (*rnd).rand_seed as *mut [u64_0; 4] as
                     *mut libc::c_void,
                 ::std::mem::size_of::<[u64_0; 4]>() as libc::c_ulong) as
                libc::c_int;
        (*rnd).rand_cnt =
            ((100000 as libc::c_int / 2 as libc::c_int) as
                 libc::c_ulonglong).wrapping_add((*rnd).rand_seed[1 as
                                                                      libc::c_int
                                                                      as
                                                                      usize].wrapping_rem(100000
                                                                                              as
                                                                                              libc::c_int
                                                                                              as
                                                                                              libc::c_ulonglong))
                as u32_0
    }
    let mut unbiased_rnd: u64_0 = 0;
    loop  {
        unbiased_rnd = afl_rand_next(rnd);
        if !(unbiased_rnd >=
                 (18446744073709551615 as libc::c_ulong as
                      libc::c_ulonglong).wrapping_sub((18446744073709551615 as
                                                           libc::c_ulong as
                                                           libc::c_ulonglong).wrapping_rem(limit)))
           {
            break ;
        }
    }
    return unbiased_rnd.wrapping_rem(limit);
}
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
static mut XXH_PRIME64_4: xxh_u64 =
    0x85ebca77c2b2ae63 as libc::c_ulonglong as xxh_u64;
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
            let fresh1 = ptr;
            ptr = ptr.offset(1);
            h64 ^= (*fresh1 as libc::c_ulong).wrapping_mul(XXH_PRIME64_5);
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
                        current_block_221 = 3009017103443065176;
                    }
                    16 => { current_block_221 = 3009017103443065176; }
                    8 => { current_block_221 = 16383797545558020236; }
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
                        current_block_221 = 8223123178938535296;
                    }
                    20 => { current_block_221 = 8223123178938535296; }
                    12 => { current_block_221 = 2098866072637438281; }
                    4 => { current_block_221 = 16032006980801283503; }
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
                        current_block_221 = 14088773652436765153;
                    }
                    17 => { current_block_221 = 14088773652436765153; }
                    9 => { current_block_221 = 5648010546727238795; }
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
                        current_block_221 = 9238930168137955545;
                    }
                    21 => { current_block_221 = 9238930168137955545; }
                    13 => { current_block_221 = 1363518629413258681; }
                    5 => { current_block_221 = 16476895318783312317; }
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
                        current_block_221 = 12891125997724673195;
                    }
                    18 => { current_block_221 = 12891125997724673195; }
                    10 => { current_block_221 = 6187460035423770001; }
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
                        current_block_221 = 2406527729975741273;
                    }
                    22 => { current_block_221 = 2406527729975741273; }
                    14 => { current_block_221 = 10100697415310866218; }
                    6 => { current_block_221 = 366167820972203224; }
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
                        current_block_221 = 17257137101339889389;
                    }
                    19 => { current_block_221 = 17257137101339889389; }
                    11 => { current_block_221 = 9673264076476189912; }
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
                        current_block_221 = 11084876405037574633;
                    }
                    23 => { current_block_221 = 11084876405037574633; }
                    15 => { current_block_221 = 5825487625081098988; }
                    7 => { current_block_221 = 4106984966160723442; }
                    3 => { current_block_221 = 18387648163930220037; }
                    2 => { current_block_221 = 8983919349874786749; }
                    1 => { current_block_221 = 2801475800627755398; }
                    0 => { current_block_221 = 2848451063551427030; }
                    _ => { break 's_1165 ; }
                }
                match current_block_221 {
                    3009017103443065176 => {
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
                        current_block_221 = 16383797545558020236;
                    }
                    8223123178938535296 => {
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
                        current_block_221 = 2098866072637438281;
                    }
                    14088773652436765153 => {
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
                        current_block_221 = 5648010546727238795;
                    }
                    9238930168137955545 => {
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
                        current_block_221 = 1363518629413258681;
                    }
                    12891125997724673195 => {
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
                        current_block_221 = 6187460035423770001;
                    }
                    2406527729975741273 => {
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
                        current_block_221 = 10100697415310866218;
                    }
                    17257137101339889389 => {
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
                        current_block_221 = 9673264076476189912;
                    }
                    11084876405037574633 => {
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
                        current_block_221 = 5825487625081098988;
                    }
                    _ => { }
                }
                match current_block_221 {
                    9673264076476189912 => {
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
                        return XXH64_avalanche(h64)
                    }
                    6187460035423770001 => {
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
                        return XXH64_avalanche(h64)
                    }
                    5648010546727238795 => {
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
                    16383797545558020236 => {
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
                    2098866072637438281 => {
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
                        current_block_221 = 16032006980801283503;
                    }
                    1363518629413258681 => {
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
                        current_block_221 = 16476895318783312317;
                    }
                    10100697415310866218 => {
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
                        current_block_221 = 366167820972203224;
                    }
                    5825487625081098988 => {
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
                        current_block_221 = 4106984966160723442;
                    }
                    _ => { }
                }
                match current_block_221 {
                    366167820972203224 => {
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
                        return XXH64_avalanche(h64)
                    }
                    16476895318783312317 => {
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
                        return XXH64_avalanche(h64)
                    }
                    16032006980801283503 => {
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
                    4106984966160723442 => {
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
                        current_block_221 = 18387648163930220037;
                    }
                    _ => { }
                }
                match current_block_221 {
                    18387648163930220037 => {
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
                        current_block_221 = 8983919349874786749;
                    }
                    _ => { }
                }
                match current_block_221 {
                    8983919349874786749 => {
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
                                             libc::c_int).wrapping_mul(XXH_PRIME64_1);
                        current_block_221 = 2801475800627755398;
                    }
                    _ => { }
                }
                match current_block_221 {
                    2801475800627755398 => {
                        let fresh13 = ptr;
                        ptr = ptr.offset(1);
                        h64 ^=
                            (*fresh13 as
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
// We start with the implementation of queue_entry functions here.
#[no_mangle]
pub unsafe extern "C" fn afl_entry_init(mut entry: *mut afl_entry_t,
                                        mut input: *mut afl_input_t,
                                        mut info: *mut afl_entry_info_t)
 -> afl_ret_t {
    (*entry).input = input;
    if info.is_null() {
        (*entry).info =
            calloc(1 as libc::c_int as libc::c_ulong,
                   ::std::mem::size_of::<afl_entry_info_t>() as libc::c_ulong)
                as *mut afl_entry_info_t;
        if (*entry).info.is_null() { return AFL_RET_ALLOC }
        (*entry).info_calloc = 1 as libc::c_int != 0
    } else { (*entry).info = info }
    (*entry).funcs.get_input =
        Some(afl_entry_get_input as
                 unsafe extern "C" fn(_: *mut afl_entry_t)
                     -> *mut afl_input_t);
    (*entry).funcs.get_next =
        Some(afl_entry_get_next as
                 unsafe extern "C" fn(_: *mut afl_entry_t)
                     -> *mut afl_entry_t);
    (*entry).funcs.get_prev =
        Some(afl_entry_get_prev as
                 unsafe extern "C" fn(_: *mut afl_entry_t)
                     -> *mut afl_entry_t);
    (*entry).funcs.get_parent =
        Some(afl_entry_get_parent as
                 unsafe extern "C" fn(_: *mut afl_entry_t)
                     -> *mut afl_entry_t);
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_entry_deinit(mut entry: *mut afl_entry_t) {
    /* We remove the element from the linked-list */
    if !(*entry).next.is_null() { (*(*entry).next).prev = (*entry).prev }
    if !(*entry).prev.is_null() { (*(*entry).prev).next = (*entry).next }
    /* we also delete the input associated with it */
    (*(*entry).input).funcs.delete.expect("non-null function pointer")((*entry).input);
    /* and the info structure */
    if (*entry).info_calloc { free((*entry).info as *mut libc::c_void); };
    /*
  // Unneeded as the structure is free'd via the macro
  entry->next = NULL;
  entry->prev = NULL;
  entry->queue = NULL;
  entry->parent = NULL;
  entry->info = NULL;
  entry->input = NULL;
  */
}
// AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_queue_feedback, AFL_DECL_PARAMS(afl_feedback_t *feedback, char *name),
//                                   AFL_CALL_PARAMS(feedback, name));
// Default implementations for the functions for queue_entry vtable
// Default implementations for the queue entry vtable functions
#[no_mangle]
pub unsafe extern "C" fn afl_entry_get_input(mut entry: *mut afl_entry_t)
 -> *mut afl_input_t {
    return (*entry).input;
}
#[no_mangle]
pub unsafe extern "C" fn afl_entry_get_next(mut entry: *mut afl_entry_t)
 -> *mut afl_entry_t {
    return (*entry).next;
}
#[no_mangle]
pub unsafe extern "C" fn afl_entry_get_prev(mut entry: *mut afl_entry_t)
 -> *mut afl_entry_t {
    return (*entry).prev;
}
#[no_mangle]
pub unsafe extern "C" fn afl_entry_get_parent(mut entry: *mut afl_entry_t)
 -> *mut afl_entry_t {
    return (*entry).parent;
}
// We implement the queue based functions now.
#[no_mangle]
pub unsafe extern "C" fn afl_queue_init(mut queue: *mut afl_queue_t)
 -> afl_ret_t {
    (*queue).entries = 0 as *mut *mut afl_entry_t;
    (*queue).save_to_files = 0 as libc::c_int != 0;
    (*queue).fuzz_started = 0 as libc::c_int != 0;
    (*queue).entries_count = 0 as libc::c_int as size_t;
    (*queue).base = 0 as *mut afl_entry_t;
    (*queue).current = 0 as libc::c_int as u64_0;
    memset((*queue).dirpath.as_mut_ptr() as *mut libc::c_void,
           0 as libc::c_int, 4096 as libc::c_int as libc::c_ulong);
    (*queue).funcs.insert =
        Some(afl_queue_insert as
                 unsafe extern "C" fn(_: *mut afl_queue_t,
                                      _: *mut afl_entry_t) -> afl_ret_t);
    (*queue).funcs.get_size =
        Some(afl_queue_get_size as
                 unsafe extern "C" fn(_: *mut afl_queue_t) -> size_t);
    (*queue).funcs.get_dirpath =
        Some(afl_queue_get_dirpath as
                 unsafe extern "C" fn(_: *mut afl_queue_t)
                     -> *mut libc::c_char);
    (*queue).funcs.get_names_id =
        Some(afl_queue_get_names_id as
                 unsafe extern "C" fn(_: *mut afl_queue_t) -> size_t);
    (*queue).funcs.get_save_to_files =
        Some(afl_queue_should_save_to_file as
                 unsafe extern "C" fn(_: *mut afl_queue_t) -> bool);
    (*queue).funcs.set_dirpath =
        Some(afl_queue_set_dirpath as
                 unsafe extern "C" fn(_: *mut afl_queue_t,
                                      _: *mut libc::c_char) -> ());
    (*queue).funcs.set_engine =
        Some(afl_queue_set_engine as
                 unsafe extern "C" fn(_: *mut afl_queue_t,
                                      _: *mut afl_engine_t) -> ());
    (*queue).funcs.get_next_in_queue =
        Some(afl_queue_next_base_queue as
                 unsafe extern "C" fn(_: *mut afl_queue_t, _: libc::c_int)
                     -> *mut afl_entry_t);
    (*queue).funcs.get_queue_entry =
        Some(afl_queue_get_entry as
                 unsafe extern "C" fn(_: *mut afl_queue_t, _: u32_0)
                     -> *mut afl_entry_t);
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_deinit(mut queue: *mut afl_queue_t) {
    /*TODO: Clear the queue entries too here*/
    let mut entry: *mut afl_entry_t = (*queue).base;
    while !entry.is_null() {
        /* Grab the next entry of queue */
        let mut next_entry: *mut afl_entry_t = (*entry).next;
        /* We destroy the queue, since none of the entries have references anywhere
     * else anyways */
        afl_entry_delete(entry);
        entry = next_entry
    }
    afl_free((*queue).entries as *mut libc::c_void);
    (*queue).base = 0 as *mut afl_entry_t;
    (*queue).current = 0 as libc::c_int as u64_0;
    (*queue).entries_count = 0 as libc::c_int as size_t;
    (*queue).fuzz_started = 0 as libc::c_int != 0;
}
/* *** Possible error cases here? *** */
#[no_mangle]
pub unsafe extern "C" fn afl_queue_insert(mut queue: *mut afl_queue_t,
                                          mut entry: *mut afl_entry_t)
 -> afl_ret_t {
    if (*entry).input.is_null() {
        // Never add an entry with NULL input, something's wrong!
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mQueue entry with NULL input\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        return AFL_RET_NULL_PTR
    }
    // Before we add the entry to the queue, we call the custom mutators
  // get_next_in_queue function, so that it can gain some extra info from the
  // fuzzed queue(especially helpful in case of grammar mutator, e.g see hogfuzz
  // mutator AFL++)
    let mut fuzz_one: *mut afl_fuzz_one_t = (*(*queue).engine).fuzz_one;
    if !fuzz_one.is_null() {
        let mut i: size_t = 0;
        i = 0 as libc::c_int as size_t;
        while i < (*fuzz_one).stages_count {
            let mut stage: *mut afl_stage_t =
                *(*fuzz_one).stages.offset(i as isize);
            let mut j: size_t = 0;
            j = 0 as libc::c_int as size_t;
            while j < (*stage).mutators_count {
                if (**(*stage).mutators.offset(j as
                                                   isize)).funcs.custom_queue_new_entry.is_some()
                   {
                    (**(*stage).mutators.offset(j as
                                                    isize)).funcs.custom_queue_new_entry.expect("non-null function pointer")(*(*stage).mutators.offset(j
                                                                                                                                                           as
                                                                                                                                                           isize),
                                                                                                                             entry);
                }
                j = j.wrapping_add(1)
            }
            i = i.wrapping_add(1)
        }
    }
    (*queue).entries_count = (*queue).entries_count.wrapping_add(1);
    (*queue).entries =
        afl_realloc((*queue).entries as *mut libc::c_void,
                    (*queue).entries_count.wrapping_mul(::std::mem::size_of::<*mut afl_entry_t>()
                                                            as libc::c_ulong))
            as *mut *mut afl_entry_t;
    if (*queue).entries.is_null() { return AFL_RET_ALLOC }
    let ref mut fresh14 =
        *(*queue).entries.offset((*queue).entries_count.wrapping_sub(1 as
                                                                         libc::c_int
                                                                         as
                                                                         libc::c_ulong)
                                     as isize);
    *fresh14 = entry;
    /* Let's save the entry to disk */
    if (*queue).save_to_files as libc::c_int != 0 &&
           (*queue).dirpath[0 as libc::c_int as usize] as libc::c_int != 0 &&
           !(*entry).on_disk {
        let mut input_data_checksum: u64_0 =
            XXH_INLINE_XXH64((*(*entry).input).bytes as *const libc::c_void,
                             (*(*entry).input).len,
                             0xa5b35705 as libc::c_uint as XXH64_hash_t) as
                u64_0;
        snprintf((*entry).filename.as_mut_ptr(),
                 (4120 as libc::c_int - 1 as libc::c_int) as libc::c_ulong,
                 b"%s/queue-%016llx\x00" as *const u8 as *const libc::c_char,
                 (*queue).dirpath.as_mut_ptr(), input_data_checksum);
        (*(*entry).input).funcs.save_to_file.expect("non-null function pointer")((*entry).input,
                                                                                 (*entry).filename.as_mut_ptr());
        (*entry).on_disk = 1 as libc::c_int != 0
    }
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_get_size(mut queue: *mut afl_queue_t)
 -> size_t {
    return (*queue).entries_count;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_get_dirpath(mut queue: *mut afl_queue_t)
 -> *mut libc::c_char {
    return (*queue).dirpath.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_get_names_id(mut queue: *mut afl_queue_t)
 -> size_t {
    return (*queue).names_id;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_should_save_to_file(mut queue:
                                                           *mut afl_queue_t)
 -> bool {
    return (*queue).save_to_files;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_set_dirpath(mut queue: *mut afl_queue_t,
                                               mut new_dirpath:
                                                   *mut libc::c_char) {
    if !new_dirpath.is_null() {
        strcpy((*queue).dirpath.as_mut_ptr(), new_dirpath);
        /* Let's create the directory if it's not already created */
        let mut dir: stat =
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
        if !(stat((*queue).dirpath.as_mut_ptr(), &mut dir) == 0 as libc::c_int
                 &&
                 dir.st_mode & 0o170000 as libc::c_int as libc::c_uint ==
                     0o40000 as libc::c_int as libc::c_uint) {
            if mkdir((*queue).dirpath.as_mut_ptr(),
                     0o777 as libc::c_int as __mode_t) != 0 as libc::c_int {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mError creating queue directory\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            }
        }
    } else {
        memset((*queue).dirpath.as_mut_ptr() as *mut libc::c_void,
               0 as libc::c_int, 4096 as libc::c_int as libc::c_ulong);
        // We are unsetting the directory path
    }
    (*queue).save_to_files = 1 as libc::c_int != 0;
    // If the dirpath is empty, we make the save_to_files bool as false
    if (*queue).dirpath[0 as libc::c_int as usize] == 0 {
        (*queue).save_to_files = 0 as libc::c_int != 0
    };
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_set_engine(mut queue: *mut afl_queue_t,
                                              mut engine: *mut afl_engine_t) {
    (*queue).engine = engine;
    if !engine.is_null() { (*queue).engine_id = (*engine).id as libc::c_int };
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_get_entry(mut queue: *mut afl_queue_t,
                                             mut entry: u32_0)
 -> *mut afl_entry_t {
    if (*queue).entries_count <= entry as libc::c_ulong {
        return 0 as *mut afl_entry_t
    }
    return *(*queue).entries.offset(entry as isize);
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_next_base_queue(mut queue:
                                                       *mut afl_queue_t,
                                                   mut engine_id: libc::c_int)
 -> *mut afl_entry_t {
    if (*queue).entries_count != 0 {
        let mut current: *mut afl_entry_t =
            *(*queue).entries.offset((*queue).current as isize);
        if engine_id != (*queue).engine_id &&
               (*(*current).info).skip_entry as libc::c_int != 0 {
            return current
        }
        // If some other engine grabs from the queue, don't update the queue's
    // current entry
    // If we reach the end of queue, start from beginning
        (*queue).current =
            (*queue).current.wrapping_add(1 as libc::c_int as
                                              libc::c_ulonglong).wrapping_rem((*queue).entries_count
                                                                                  as
                                                                                  libc::c_ulonglong);
        return current
    } else {
        // Queue empty :(
        return 0 as *mut afl_entry_t
    };
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_feedback_init(mut feedback_queue:
                                                     *mut afl_queue_feedback_t,
                                                 mut feedback:
                                                     *mut afl_feedback_t,
                                                 mut name: *mut libc::c_char)
 -> afl_ret_t {
    afl_queue_init(&mut (*feedback_queue).base);
    (*feedback_queue).feedback = feedback;
    if !feedback.is_null() { (*feedback).queue = feedback_queue }
    if name.is_null() {
        name =
            b"\x00" as *const u8 as *const libc::c_char as *mut libc::c_char
    }
    (*feedback_queue).name = name;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_feedback_deinit(mut feedback_queue:
                                                       *mut afl_queue_feedback_t) {
    (*feedback_queue).feedback = 0 as *mut afl_feedback_t;
    afl_queue_deinit(&mut (*feedback_queue).base);
    (*feedback_queue).name = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_global_init(mut global_queue:
                                                   *mut afl_queue_global_t)
 -> afl_ret_t {
    afl_queue_init(&mut (*global_queue).base);
    (*global_queue).feedback_queues_count = 0 as libc::c_int as size_t;
    (*global_queue).feedback_queues = 0 as *mut *mut afl_queue_feedback_t;
    (*global_queue).base.funcs.set_engine =
        Some(afl_queue_global_set_engine as
                 unsafe extern "C" fn(_: *mut afl_queue_t,
                                      _: *mut afl_engine_t) -> ());
    (*global_queue).funcs.add_feedback_queue =
        Some(afl_queue_global_add_feedback_queue as
                 unsafe extern "C" fn(_: *mut afl_queue_global_t,
                                      _: *mut afl_queue_feedback_t)
                     -> afl_ret_t);
    (*global_queue).funcs.schedule =
        Some(afl_queue_global_schedule as
                 unsafe extern "C" fn(_: *mut afl_queue_global_t)
                     -> libc::c_int);
    (*global_queue).base.funcs.get_next_in_queue =
        Some(afl_queue_next_global_queue as
                 unsafe extern "C" fn(_: *mut afl_queue_t, _: libc::c_int)
                     -> *mut afl_entry_t);
    (*global_queue).base.funcs.set_engine =
        Some(afl_queue_global_set_engine as
                 unsafe extern "C" fn(_: *mut afl_queue_t,
                                      _: *mut afl_engine_t) -> ());
    return AFL_RET_SUCCESS;
}
/* Register this as global queue for the engine.
TODO: Make this a method of engine instead */
/* TODO: ADD defualt implementation for the schedule function based on random.
 */
#[no_mangle]
pub unsafe extern "C" fn afl_queue_global_deinit(mut global_queue:
                                                     *mut afl_queue_global_t) {
    /* Should we also deinit the feedback queues?? */
    let mut i: size_t = 0;
    afl_queue_deinit(&mut (*global_queue).base);
    i = 0 as libc::c_int as size_t;
    while i < (*global_queue).feedback_queues_count {
        let ref mut fresh15 =
            *(*global_queue).feedback_queues.offset(i as isize);
        *fresh15 = 0 as *mut afl_queue_feedback_t;
        i = i.wrapping_add(1)
    }
    afl_free((*global_queue).feedback_queues as *mut libc::c_void);
    (*global_queue).feedback_queues = 0 as *mut *mut afl_queue_feedback_t;
    (*global_queue).feedback_queues_count = 0 as libc::c_int as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_queue_global_add_feedback_queue(mut global_queue:
                                                                 *mut afl_queue_global_t,
                                                             mut feedback_queue:
                                                                 *mut afl_queue_feedback_t)
 -> afl_ret_t {
    (*global_queue).feedback_queues_count =
        (*global_queue).feedback_queues_count.wrapping_add(1);
    (*global_queue).feedback_queues =
        afl_realloc((*global_queue).feedback_queues as *mut libc::c_void,
                    (*global_queue).feedback_queues_count.wrapping_mul(::std::mem::size_of::<*mut afl_queue_feedback_t>()
                                                                           as
                                                                           libc::c_ulong))
            as *mut *mut afl_queue_feedback_t;
    if (*global_queue).feedback_queues.is_null() {
        (*global_queue).feedback_queues_count = 0 as libc::c_int as size_t;
        return AFL_RET_ALLOC
    }
    let ref mut fresh16 =
        *(*global_queue).feedback_queues.offset((*global_queue).feedback_queues_count.wrapping_sub(1
                                                                                                       as
                                                                                                       libc::c_int
                                                                                                       as
                                                                                                       libc::c_ulong)
                                                    as isize);
    *fresh16 = feedback_queue;
    let mut engine: *mut afl_engine_t = (*global_queue).base.engine;
    (*feedback_queue).base.funcs.set_engine.expect("non-null function pointer")(&mut (*feedback_queue).base,
                                                                                engine);
    return AFL_RET_SUCCESS;
}
// Function to get next entry from queue, we override the base_queue
// implementation
#[no_mangle]
pub unsafe extern "C" fn afl_queue_next_global_queue(mut queue:
                                                         *mut afl_queue_t,
                                                     mut engine_id:
                                                         libc::c_int)
 -> *mut afl_entry_t {
    // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
    let mut global_queue: *mut afl_queue_global_t =
        queue as *mut afl_queue_global_t;
    let mut fbck_idx: libc::c_int =
        (*global_queue).funcs.schedule.expect("non-null function pointer")(global_queue);
    if fbck_idx != -(1 as libc::c_int) {
        let mut feedback_queue: *mut afl_queue_feedback_t =
            *(*global_queue).feedback_queues.offset(fbck_idx as isize);
        let mut next_entry: *mut afl_entry_t =
            (*feedback_queue).base.funcs.get_next_in_queue.expect("non-null function pointer")(&mut (*feedback_queue).base,
                                                                                               engine_id);
        if !next_entry.is_null() {
            return next_entry
        } else { return afl_queue_next_base_queue(queue, engine_id) }
    } else {
        // We don't have any more entries feedback queue, so base queue it is.
        return afl_queue_next_base_queue(queue, engine_id)
    };
}
// One global queue can have
                                           // multiple feedback queues
/*TODO: Add a map of Engine:feedback_queue
    UPDATE: Engine will have a ptr to current feedback queue rather than this*/
// Default implementations of global queue vtable functions
#[no_mangle]
pub unsafe extern "C" fn afl_queue_global_schedule(mut queue:
                                                       *mut afl_queue_global_t)
 -> libc::c_int {
    return afl_rand_below(&mut (*(*queue).base.engine).rand,
                          (*queue).feedback_queues_count as u64_0) as
               libc::c_int;
}
/* TODO: make this a method for engine instead */
#[no_mangle]
pub unsafe extern "C" fn afl_queue_global_set_engine(mut global_queue_base:
                                                         *mut afl_queue_t,
                                                     mut engine:
                                                         *mut afl_engine_t) {
    let mut i: size_t = 0;
    let mut global_queue: *mut afl_queue_global_t =
        global_queue_base as *mut afl_queue_global_t;
    // First add engine to the global queue itself
    afl_queue_set_engine(&mut (*global_queue).base, engine);
    // Set engine's queue to the global queue
    if !engine.is_null() { (*engine).global_queue = global_queue }
    i = 0 as libc::c_int as size_t;
    while i < (*global_queue).feedback_queues_count {
        // Set this engine to every feedback queue in global queue
        (**(*global_queue).feedback_queues.offset(i as
                                                      isize)).base.funcs.set_engine.expect("non-null function pointer")(&mut (**(*global_queue).feedback_queues.offset(i
                                                                                                                                                                           as
                                                                                                                                                                           isize)).base,
                                                                                                                        engine);
        i = i.wrapping_add(1)
    };
}
