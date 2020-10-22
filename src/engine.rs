use ::libc;
extern "C" {
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn close(__fd: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn time(__timer: *mut time_t) -> time_t;
    #[no_mangle]
    fn afl_entry_init(_: *mut afl_entry_t, _: *mut afl_input_t,
                      _: *mut afl_entry_info_t) -> afl_ret_t;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn afl_input_init(input: *mut afl_input_t) -> afl_ret_t;
    /* Write the contents of the input which causes a crash in the target to a crashfile */
    #[no_mangle]
    fn afl_input_dump_to_crashfile(_: *mut afl_input_t, _: *mut libc::c_char)
     -> afl_ret_t;
    #[no_mangle]
    fn llmp_client_recv(client: *mut llmp_client_t) -> *mut llmp_message_t;
    /* Run `handle_file` for each file in the dirpath, recursively.
void *data will be passed to handle_file as 2nd param.
if handle_file returns false, further execution stops. */
    #[no_mangle]
    fn afl_for_each_file(dirpath: *mut libc::c_char,
                         handle_file:
                             Option<unsafe extern "C" fn(_: *mut libc::c_char,
                                                         _: *mut libc::c_void)
                                        -> bool>, data: *mut libc::c_void)
     -> afl_ret_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
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
// The params here are in_buf and out_buf.
// Mutate function
// Checks if the queue entry is to be fuzzed or not
// Post process API AFL++
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
#[inline]
unsafe extern "C" fn afl_entry_new(mut input: *mut afl_input_t,
                                   mut info: *mut afl_entry_info_t)
 -> *mut afl_entry_t {
    let mut ret: *mut afl_entry_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_entry_t>() as libc::c_ulong) as
            *mut afl_entry_t;
    if ret.is_null() { return 0 as *mut afl_entry_t }
    if afl_entry_init(ret, input, info) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_entry_t
    }
    return ret;
}
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
            current_block_17 = 6100629464535663547;
        }
        4 => { current_block_17 = 6100629464535663547; }
        6 => { current_block_17 = 10219713304939013295; }
        12 => { current_block_17 = 3089853308412511092; }
        _ => {
            return b"Unknown error. Please report this bug!\x00" as *const u8
                       as *const libc::c_char as *mut libc::c_char
        }
    }
    match current_block_17 {
        6100629464535663547 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Error opening file\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 10219713304939013295;
        }
        _ => { }
    }
    match current_block_17 {
        10219713304939013295 =>
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
unsafe extern "C" fn afl_rand_deinit(mut rnd: *mut afl_rand_t) {
    if (*rnd).dev_urandom_fd != 0 { close((*rnd).dev_urandom_fd); };
}
#[inline]
unsafe extern "C" fn afl_rand_init(mut rnd: *mut afl_rand_t) -> afl_ret_t {
    memset(rnd as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<afl_rand_t>() as libc::c_ulong);
    (*rnd).dev_urandom_fd =
        open(b"/dev/urandom\x00" as *const u8 as *const libc::c_char,
             0 as libc::c_int);
    if (*rnd).dev_urandom_fd == 0 { return AFL_RET_FILE_OPEN_ERROR }
    (*rnd).fixed_seed = 0 as libc::c_int != 0;
    afl_rand_below(rnd, 1 as libc::c_int as u64_0);
    return AFL_RET_SUCCESS;
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
unsafe extern "C" fn afl_rand_rotl(x: u64_0, mut k: libc::c_int) -> u64_0 {
    return x << k | x >> 64 as libc::c_int - k;
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
#[no_mangle]
pub unsafe extern "C" fn afl_engine_init(mut engine: *mut afl_engine_t,
                                         mut executor: *mut afl_executor_t,
                                         mut fuzz_one: *mut afl_fuzz_one_t,
                                         mut global_queue:
                                             *mut afl_queue_global_t)
 -> afl_ret_t {
    (*engine).executor =
        executor; // Initialize bound cpu to -1 (0xffffffff) bit mask for non affinity
    (*engine).fuzz_one = fuzz_one;
    (*engine).global_queue = global_queue;
    (*engine).feedbacks = 0 as *mut *mut afl_feedback_t;
    (*engine).feedbacks_count = 0 as libc::c_int as u64_0;
    (*engine).executions = 0 as libc::c_int as u64_0;
    (*engine).cpu_bound = -(1 as libc::c_int);
    if !global_queue.is_null() {
        (*global_queue).base.funcs.set_engine.expect("non-null function pointer")(&mut (*global_queue).base,
                                                                                  engine);
    }
    (*engine).funcs.get_queue =
        Some(afl_engine_get_queue as
                 unsafe extern "C" fn(_: *mut afl_engine_t)
                     -> *mut afl_queue_global_t);
    (*engine).funcs.get_execs =
        Some(afl_get_execs as
                 unsafe extern "C" fn(_: *mut afl_engine_t) -> u64_0);
    (*engine).funcs.get_fuzz_one =
        Some(afl_engine_get_fuzz_one as
                 unsafe extern "C" fn(_: *mut afl_engine_t)
                     -> *mut afl_fuzz_one_t);
    (*engine).funcs.get_start_time =
        Some(afl_engine_get_start_time as
                 unsafe extern "C" fn(_: *mut afl_engine_t) -> u64_0);
    (*engine).funcs.set_fuzz_one =
        Some(afl_set_fuzz_one as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut afl_fuzz_one_t) -> ());
    (*engine).funcs.add_feedback =
        Some(afl_engine_add_feedback as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut afl_feedback_t) -> afl_ret_t);
    (*engine).funcs.set_global_queue =
        Some(afl_set_global_queue as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut afl_queue_global_t) -> ());
    (*engine).funcs.execute =
        Some(afl_engine_execute as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut afl_input_t) -> u8_0);
    (*engine).funcs.load_testcases_from_dir =
        Some(afl_engine_load_testcases_from_dir as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut libc::c_char) -> afl_ret_t);
    (*engine).funcs.loop_0 =
        Some(afl_engine_loop as
                 unsafe extern "C" fn(_: *mut afl_engine_t) -> afl_ret_t);
    (*engine).funcs.handle_new_message =
        Some(afl_engine_handle_new_message as
                 unsafe extern "C" fn(_: *mut afl_engine_t,
                                      _: *mut llmp_message_t) -> afl_ret_t);
    let mut ret: afl_ret_t = afl_rand_init(&mut (*engine).rand);
    (*engine).buf = 0 as *mut u8_0;
    if ret as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        return ret
    }
    (*engine).id = afl_rand_next(&mut (*engine).rand) as u32_0;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_deinit(mut engine: *mut afl_engine_t) {
    let mut i: size_t = 0;
    /* Let's free everything associated with the engine here, except the queues,
   * should we leave anything else? */
    afl_rand_deinit(&mut (*engine).rand);
    (*engine).fuzz_one = 0 as *mut afl_fuzz_one_t;
    (*engine).executor = 0 as *mut afl_executor_t;
    (*engine).global_queue = 0 as *mut afl_queue_global_t;
    i = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        let ref mut fresh1 = *(*engine).feedbacks.offset(i as isize);
        *fresh1 = 0 as *mut afl_feedback_t;
        i = i.wrapping_add(1)
    }
    afl_free((*engine).feedbacks as *mut libc::c_void);
    (*engine).feedbacks = 0 as *mut *mut afl_feedback_t;
    (*engine).start_time = 0 as libc::c_int as u64_0;
    (*engine).current_feedback_queue = 0 as *mut afl_queue_feedback_t;
    (*engine).feedbacks_count = 0 as libc::c_int as u64_0;
    (*engine).executions = 0 as libc::c_int as u64_0;
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_get_queue(mut engine: *mut afl_engine_t)
 -> *mut afl_queue_global_t {
    return (*engine).global_queue;
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_get_fuzz_one(mut engine:
                                                     *mut afl_engine_t)
 -> *mut afl_fuzz_one_t {
    return (*engine).fuzz_one;
}
#[no_mangle]
pub unsafe extern "C" fn afl_get_execs(mut engine: *mut afl_engine_t)
 -> u64_0 {
    return (*engine).executions;
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_get_start_time(mut engine:
                                                       *mut afl_engine_t)
 -> u64_0 {
    return (*engine).start_time;
}
#[no_mangle]
pub unsafe extern "C" fn afl_set_fuzz_one(mut engine: *mut afl_engine_t,
                                          mut fuzz_one: *mut afl_fuzz_one_t) {
    (*engine).fuzz_one = fuzz_one;
    if !fuzz_one.is_null() {
        (*fuzz_one).funcs.set_engine.expect("non-null function pointer")((*engine).fuzz_one,
                                                                         engine);
    };
}
#[no_mangle]
pub unsafe extern "C" fn afl_set_global_queue(mut engine: *mut afl_engine_t,
                                              mut global_queue:
                                                  *mut afl_queue_global_t) {
    (*engine).global_queue = global_queue;
    if !global_queue.is_null() {
        (*global_queue).base.funcs.set_engine.expect("non-null function pointer")(&mut (*global_queue).base,
                                                                                  engine);
    };
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_add_feedback(mut engine:
                                                     *mut afl_engine_t,
                                                 mut feedback:
                                                     *mut afl_feedback_t)
 -> afl_ret_t {
    (*engine).feedbacks_count = (*engine).feedbacks_count.wrapping_add(1);
    (*engine).feedbacks =
        afl_realloc((*engine).feedbacks as *mut libc::c_void,
                    (*engine).feedbacks_count.wrapping_mul(::std::mem::size_of::<*mut afl_feedback_t>()
                                                               as
                                                               libc::c_ulong
                                                               as
                                                               libc::c_ulonglong)
                        as size_t) as *mut *mut afl_feedback_t;
    if (*engine).feedbacks.is_null() { return AFL_RET_ALLOC }
    let ref mut fresh2 =
        *(*engine).feedbacks.offset((*engine).feedbacks_count.wrapping_sub(1
                                                                               as
                                                                               libc::c_int
                                                                               as
                                                                               libc::c_ulonglong)
                                        as isize);
    *fresh2 = feedback;
    return AFL_RET_SUCCESS;
}
unsafe extern "C" fn afl_engine_handle_single_testcase_load(mut infile:
                                                                *mut libc::c_char,
                                                            mut data:
                                                                *mut libc::c_void)
 -> bool {
    let mut engine: *mut afl_engine_t = data as *mut afl_engine_t;
    let mut input: *mut afl_input_t = afl_input_new();
    if input.is_null() {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [src/engine.c:166] \x1b[0mError allocating input %s\x00"
                   as *const u8 as *const libc::c_char, infile);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    let mut err: afl_ret_t =
        (*input).funcs.load_from_file.expect("non-null function pointer")(input,
                                                                          infile);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [src/engine.c:177] \x1b[0mAFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mError loading seed %s: %s\x00"
                   as *const u8 as *const libc::c_char, infile,
               afl_ret_stringify(err));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        free(input as *mut libc::c_void);
        return 0 as libc::c_int != 0
    }
    /*
    afl_ret_t run_result = engine->funcs.execute(engine, input);

    if (run_result == AFL_RET_SUCCESS) {

      if (engine->verbose) OKF("Loaded seed %s", infile);

    } else {

      WARNF("Error loading seed %s", infile);
      // free(input); // should we?
      return false;

    }

    // We add the corpus to the queue initially for all the feedback queues

    size_t i;
    for (i = 0; i < engine->feedbacks_count; ++i) {

      afl_entry_t *entry = afl_entry_new(input);
      if (!entry) {

        DBG("Error allocating entry.");
        return false;

      }

      engine->feedbacks[i]->queue->base.funcs.insert(&engine->feedbacks[i]->queue->base, entry);

    }

    //if (run_result == AFL_RET_WRITE_TO_CRASH) { if (engine->verbose) WARNF("Crashing input found in initial corpus,
    this is usually not a good idea.\n"); }
  */
  /* We add the corpus to the global queue */
    let mut entry: *mut afl_entry_t =
        afl_entry_new(input, 0 as *mut afl_entry_info_t);
    if entry.is_null() {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [src/engine.c:218] \x1b[0mError allocating entry.\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return 0 as libc::c_int != 0
    }
    (*(*engine).global_queue).base.funcs.insert.expect("non-null function pointer")(&mut (*(*engine).global_queue).base,
                                                                                    entry);
    if (*engine).verbose != 0 {
        printf(b"\x1b[1;92m[+] \x1b[0mLoaded seed %s\x00" as *const u8 as
                   *const libc::c_char, infile);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    }
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_load_testcases_from_dir(mut engine:
                                                                *mut afl_engine_t,
                                                            mut dirpath:
                                                                *mut libc::c_char)
 -> afl_ret_t {
    return afl_for_each_file(dirpath,
                             Some(afl_engine_handle_single_testcase_load as
                                      unsafe extern "C" fn(_:
                                                               *mut libc::c_char,
                                                           _:
                                                               *mut libc::c_void)
                                          -> bool),
                             engine as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_handle_new_message(mut engine:
                                                           *mut afl_engine_t,
                                                       mut msg:
                                                           *mut llmp_message_t)
 -> afl_ret_t {
    /* Default implementation, handles only new queue entry messages. Users have
   * liberty with this function */
    if (*msg).tag == 0xc0added1 as libc::c_uint {
        let mut input: *mut afl_input_t = afl_input_new();
        if input.is_null() { return AFL_RET_ALLOC }
        /* the msg will stick around forever, so this is safe. */
        (*input).bytes = (*msg).buf.as_mut_ptr();
        (*input).len = (*msg).buf_len;
        let mut info_ptr: *mut afl_entry_info_t =
            (*msg).buf.as_mut_ptr().offset((*msg).buf_len as isize) as
                *mut afl_entry_info_t;
        let mut new_entry: *mut afl_entry_t = afl_entry_new(input, info_ptr);
        /* Users can experiment here, adding entries to different queues based on
     * the message tag. Right now, let's just add it to all queues*/
        let mut i: size_t = 0 as libc::c_int as size_t;
        (*(*engine).global_queue).base.funcs.insert.expect("non-null function pointer")(&mut (*(*engine).global_queue).base,
                                                                                        new_entry);
        let mut feedback_queues: *mut *mut afl_queue_feedback_t =
            (*(*engine).global_queue).feedback_queues;
        i = 0 as libc::c_int as size_t;
        while i < (*(*engine).global_queue).feedback_queues_count {
            (**feedback_queues.offset(i as
                                          isize)).base.funcs.insert.expect("non-null function pointer")(&mut (**feedback_queues.offset(i
                                                                                                                                           as
                                                                                                                                           isize)).base,
                                                                                                        new_entry);
            i = i.wrapping_add(1)
        }
    }
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_execute(mut engine: *mut afl_engine_t,
                                            mut input: *mut afl_input_t)
 -> u8_0 {
    let mut i: size_t = 0;
    let mut executor: *mut afl_executor_t = (*engine).executor;
    (*executor).funcs.observers_reset.expect("non-null function pointer")(executor);
    (*executor).funcs.place_input_cb.expect("non-null function pointer")(executor,
                                                                         input);
    if (*engine).start_time == 0 as libc::c_int as libc::c_ulonglong {
        (*engine).start_time = time(0 as *mut time_t) as u64_0
    }
    let mut run_result: afl_exit_t =
        (*executor).funcs.run_target_cb.expect("non-null function pointer")(executor);
    (*engine).executions = (*engine).executions.wrapping_add(1);
    /* We've run the target with the executor, we can now simply postExec call the
   * observation channels*/
    i = 0 as libc::c_int as size_t;
    while i < (*executor).observors_count as libc::c_ulong {
        let mut obs_channel: *mut afl_observer_t =
            *(*executor).observors.offset(i as isize);
        if (*obs_channel).funcs.post_exec.is_some() {
            (*obs_channel).funcs.post_exec.expect("non-null function pointer")(*(*executor).observors.offset(i
                                                                                                                 as
                                                                                                                 isize),
                                                                               engine);
        }
        i = i.wrapping_add(1)
    }
    // Now based on the return of executor's run target, we basically return an
  // afl_ret_t type to the callee
    match run_result as libc::c_uint {
        0 | 8 => { return AFL_RET_SUCCESS as libc::c_int as u8_0 }
        _ => {
            let mut global_queue: *mut afl_queue_global_t =
                afl_engine_get_queue(engine);
            if afl_input_dump_to_crashfile((*executor).current_input,
                                           (*global_queue).base.dirpath.as_mut_ptr())
                   as libc::c_uint ==
                   AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                (*engine).crashes = (*engine).crashes.wrapping_add(1)
            }
            return AFL_RET_WRITE_TO_CRASH as libc::c_int as u8_0
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn afl_engine_loop(mut engine: *mut afl_engine_t)
 -> afl_ret_t {
    loop  {
        let mut fuzz_one_ret: afl_ret_t =
            (*(*engine).fuzz_one).funcs.perform.expect("non-null function pointer")((*engine).fuzz_one);
        /* let's call this engine's message handler */
        if (*engine).funcs.handle_new_message.is_some() {
            /* Let's read the broadcasted messages now */
            let mut msg: *mut llmp_message_t = 0 as *mut llmp_message_t;
            loop  {
                msg = llmp_client_recv((*engine).llmp_client);
                if msg.is_null() { break ; }
                let mut err: afl_ret_t =
                    (*engine).funcs.handle_new_message.expect("non-null function pointer")(engine,
                                                                                           msg);
                if err as libc::c_uint !=
                       AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
                    printf(b"\x1b[0;35m[D]\x1b[1;90m [src/engine.c:332] \x1b[0mAFL_TRY returning error: %s\x00"
                               as *const u8 as *const libc::c_char,
                           afl_ret_stringify(err));
                    printf(b"\x1b[0m\n\x00" as *const u8 as
                               *const libc::c_char);
                    fflush(stdout);
                    return err
                }
            }
        }
        match fuzz_one_ret as libc::c_uint {
            13 => {
                // case AFL_RET_WRITE_TO_CRASH:
                //   // crash_write_return =
        //   // afl_input_dump_to_crashfile(engine->executor->current_input);
                //   return AFL_RET_WRITE_TO_CRASH;
                //   break;
                printf(b"NULL QUEUE\n\x00" as *const u8 as
                           *const libc::c_char);
                return fuzz_one_ret
            }
            19 => { return fuzz_one_ret }
            _ => { }
        }
    };
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
// We're keeping a pointer of feedbacks here
                                    // to save memory, consideting the original
                                    // feedback would already be allocated
// 1 if we want to bind to a cpu, 0 else 
// Input corpus directory
// Reusable buf for realloc
// Our IPC for fuzzer communication
/* TODO: Add default implementations for load_testcases and execute */
// Not sure about this functions
                                            // use-case. Was in FFF though.
/* A function which can be run just before starting the fuzzing process. This checks if the engine(and all it's
 * components) is initialized or not */
#[no_mangle]
pub unsafe extern "C" fn afl_engine_check_configuration(mut engine:
                                                            *mut afl_engine_t)
 -> afl_ret_t {
    let mut has_warning: bool = 0 as libc::c_int != 0;
    if engine.is_null() {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mEngine is null\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        return AFL_RET_NULL_PTR
    }
    /* Let's start by checking the essential parts of engine, executor, feedback(if available) */
    if (*engine).executor.is_null() {
        // WARNF("No executor present in engine-%u", engine->id);
    // goto error;
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo executor present in engine-%u\x00"
                   as *const u8 as *const libc::c_char, (*engine).id);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        has_warning = 1 as libc::c_int != 0
    }
    let mut executor: *mut afl_executor_t = (*engine).executor;
    if (*engine).global_queue.is_null() {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo global_queue present in engine-%u\x00"
                   as *const u8 as *const libc::c_char, (*engine).id);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        has_warning = 1 as libc::c_int != 0
    }
    let mut global_queue: *mut afl_queue_global_t = (*engine).global_queue;
    if (*engine).fuzz_one.is_null() {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo fuzzone present in engine-%u\x00"
                   as *const u8 as *const libc::c_char, (*engine).id);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        has_warning = 1 as libc::c_int != 0
    }
    let mut fuzz_one: *mut afl_fuzz_one_t = (*engine).fuzz_one;
    let mut i: size_t = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        if (*(*engine).feedbacks.offset(i as isize)).is_null() {
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mFeedback is NULL at %zu idx but feedback count is greater (%llu).\x00"
                       as *const u8 as *const libc::c_char, i,
                   (*engine).feedbacks_count);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
            has_warning = 1 as libc::c_int != 0;
            break ;
        } else { i = i.wrapping_add(1) }
    }
    if (*engine).llmp_client.is_null() {
        printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo llmp client present in engine-%u\x00"
                   as *const u8 as *const libc::c_char, (*engine).id);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        has_warning = 1 as libc::c_int != 0
    }
    if !executor.is_null() {
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        while i_0 < (*executor).observors_count as libc::c_ulong {
            if (*(*executor).observors.offset(i_0 as isize)).is_null() {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo observation channel present in engine-%u\x00"
                           as *const u8 as *const libc::c_char, (*engine).id);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
                has_warning = 1 as libc::c_int != 0
            }
            i_0 = i_0.wrapping_add(1)
        }
    }
    if !global_queue.is_null() {
        let mut i_1: size_t = 0 as libc::c_int as size_t;
        while i_1 < (*global_queue).feedback_queues_count {
            if (*(*global_queue).feedback_queues.offset(i_1 as
                                                            isize)).is_null()
               {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo Feedback queue present in engine-%u\x00"
                           as *const u8 as *const libc::c_char, (*engine).id);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
                has_warning = 1 as libc::c_int != 0
            }
            i_1 = i_1.wrapping_add(1)
        }
    }
    if !fuzz_one.is_null() {
        let mut i_2: size_t = 0 as libc::c_int as size_t;
        while i_2 < (*fuzz_one).stages_count {
            if (*(*fuzz_one).stages.offset(i_2 as isize)).is_null() {
                printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mNo Stage present in engine-%u\x00"
                           as *const u8 as *const libc::c_char, (*engine).id);
                printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
                has_warning = 1 as libc::c_int != 0
            }
            i_2 = i_2.wrapping_add(1)
            /* Stage needs to be checked properly */
        }
    }
    if has_warning { return AFL_RET_ERROR_INITIALIZE }
    return AFL_RET_SUCCESS;
}
