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
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
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
}
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
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
/* unique ID of this client */
/* the last message we received */
/* the current broadcast map to read from */
/* the last msg we sent */
/* Number of maps we're using */
/* The maps to write to */
/* Count of the hooks we'll call for each new shared map */
/* The hooks we'll call for each new shared map */
// This has a few parts, the first deals with crash handling.
/* afl_exit_t is for the fuzzed target, as opposed to afl_ret_t
which is for internal functions. */
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback_cov {
    pub base: afl_feedback_t,
    pub observer_cov: *mut afl_observer_covmap_t,
    pub virgin_bits: *mut u8_0,
    pub size: size_t,
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
// Default implementation of the functions
// "Constructors" and "destructors" for the feedback
/* Simple MaximizeMapFeedback implementation */
/* Coverage Feedback */
pub type afl_feedback_cov_t = afl_feedback_cov;
/* This array holds the coveragemap observation channels the feedback is looking at */
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
            current_block_17 = 9124283142998713593;
        }
        4 => { current_block_17 = 9124283142998713593; }
        6 => { current_block_17 = 9310518756776399870; }
        12 => { current_block_17 = 16840486104825400973; }
        _ => {
            return b"Unknown error. Please report this bug!\x00" as *const u8
                       as *const libc::c_char as *mut libc::c_char
        }
    }
    match current_block_17 {
        9124283142998713593 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Error opening file\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 9310518756776399870;
        }
        _ => { }
    }
    match current_block_17 {
        9310518756776399870 =>
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
pub unsafe extern "C" fn afl_feedback_init(mut feedback: *mut afl_feedback_t,
                                           mut queue:
                                               *mut afl_queue_feedback_t)
 -> afl_ret_t {
    (*feedback).queue = queue;
    (*feedback).funcs.set_feedback_queue =
        Some(afl_feedback_set_queue as
                 unsafe extern "C" fn(_: *mut afl_feedback_t,
                                      _: *mut afl_queue_feedback_t) -> ());
    (*feedback).funcs.get_feedback_queue =
        Some(afl_feedback_get_queue as
                 unsafe extern "C" fn(_: *mut afl_feedback_t)
                     -> *mut afl_queue_feedback_t);
    (*feedback).funcs.is_interesting = None;
    (*feedback).tag = 0xfeedb43e as libc::c_uint;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_deinit(mut feedback:
                                                 *mut afl_feedback_t) {
    (*feedback).tag = 0xaf1da10c as libc::c_uint;
    /* Since feedback is deinitialized, we remove it's ptr from the feedback_queue
   */
    (*feedback).queue = 0 as *mut afl_queue_feedback_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_set_queue(mut feedback:
                                                    *mut afl_feedback_t,
                                                mut queue:
                                                    *mut afl_queue_feedback_t) {
    (*feedback).queue = queue;
    if !queue.is_null() { (*queue).feedback = feedback };
}
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_get_queue(mut feedback:
                                                    *mut afl_feedback_t)
 -> *mut afl_queue_feedback_t {
    return (*feedback).queue;
}
/* Map feedback. Can be easily used with a tracebits map similar to AFL++ */
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_cov_init(mut feedback:
                                                   *mut afl_feedback_cov_t,
                                               mut queue:
                                                   *mut afl_queue_feedback_t,
                                               mut observer_cov:
                                                   *mut afl_observer_covmap_t)
 -> afl_ret_t {
    let mut size: size_t = (*observer_cov).shared_map.map_size;
    (*feedback).observer_cov = observer_cov;
    (*feedback).virgin_bits =
        calloc(1 as libc::c_int as libc::c_ulong, size) as *mut u8_0;
    if (*feedback).virgin_bits.is_null() { return AFL_RET_ALLOC }
    memset((*feedback).virgin_bits as *mut libc::c_void, 0xff as libc::c_int,
           size);
    let mut err: afl_ret_t = afl_feedback_init(&mut (*feedback).base, queue);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [src/feedback.c:87] \x1b[0mAFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        free((*feedback).virgin_bits as *mut libc::c_void);
        return err
    }
    (*feedback).size = size;
    (*feedback).base.funcs.is_interesting =
        Some(afl_feedback_cov_is_interesting as
                 unsafe extern "C" fn(_: *mut afl_feedback_t,
                                      _: *mut afl_executor_t)
                     -> libc::c_float);
    (*feedback).base.tag = 0xfeedc0f8 as libc::c_uint;
    return AFL_RET_SUCCESS;
}
/* Set virgin bits according to the map passed into the func */
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_cov_set_virgin_bits(mut feedback:
                                                              *mut afl_feedback_cov_t,
                                                          mut virgin_bits_copy_from:
                                                              *mut u8_0,
                                                          mut size: size_t)
 -> afl_ret_t {
    if size != (*(*feedback).observer_cov).shared_map.map_size {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mVirgin bitmap size may never differs from observer_covmap size\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 33],
                                         &[libc::c_char; 33]>(b"afl_feedback_cov_set_virgin_bits\x00")).as_ptr(),
               b"src/feedback.c\x00" as *const u8 as *const libc::c_char,
               103 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*feedback).virgin_bits =
        realloc((*feedback).virgin_bits as *mut libc::c_void, size) as
            *mut u8_0;
    if (*feedback).virgin_bits.is_null() {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [src/feedback.c:110] \x1b[0mFailed to alloc %ld bytes for virgin_bitmap\x00"
                   as *const u8 as *const libc::c_char, size);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        (*feedback).size = 0 as libc::c_int as size_t;
        return AFL_RET_ALLOC
    }
    memcpy((*feedback).virgin_bits as *mut libc::c_void,
           virgin_bits_copy_from as *const libc::c_void, size);
    (*feedback).size = size;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_cov_deinit(mut feedback:
                                                     *mut afl_feedback_cov_t) {
    free((*feedback).virgin_bits as *mut libc::c_void);
    (*feedback).virgin_bits = 0 as *mut u8_0;
    (*feedback).size = 0 as libc::c_int as size_t;
    afl_feedback_deinit(&mut (*feedback).base);
}
/* Set virgin bits according to the map passed into the func */
/* Returns the "interestingness" of the current feedback */
#[no_mangle]
pub unsafe extern "C" fn afl_feedback_cov_is_interesting(mut feedback:
                                                             *mut afl_feedback_t,
                                                         mut fsrv:
                                                             *mut afl_executor_t)
 -> libc::c_float {
    if (*feedback).tag != 0xfeedc0f8 as libc::c_uint {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mCalled cov_is_interesting with non-cov feeback\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 32],
                                         &[libc::c_char; 32]>(b"afl_feedback_cov_is_interesting\x00")).as_ptr(),
               b"src/feedback.c\x00" as *const u8 as *const libc::c_char,
               136 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut map_feedback: *mut afl_feedback_cov_t =
        feedback as *mut afl_feedback_cov_t;
    let mut obs_channel: *mut afl_observer_covmap_t =
        (*map_feedback).observer_cov;
    let mut current: *mut u64_0 = (*obs_channel).shared_map.map as *mut u64_0;
    let mut virgin: *mut u64_0 = (*map_feedback).virgin_bits as *mut u64_0;
    let mut i: u32_0 =
        ((*obs_channel).shared_map.map_size >> 3 as libc::c_int) as u32_0;
    /* ^WORD_SIZE_64 */
    // the map size must be a minimum of 8 bytes.
  // for variable/dynamic map sizes this is ensured in the forkserver
    let mut ret: libc::c_float = 0.0f64 as libc::c_float;
    loop  {
        let fresh0 = i;
        i = i.wrapping_sub(1);
        if !(fresh0 != 0) { break ; }
        /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */
        // the (*current) is unnecessary but speeds up the overall comparison
        if *current != 0 && *current & *virgin != 0 {
            if ret < 2 as libc::c_int as libc::c_float {
                let mut cur: *mut u8_0 = current as *mut u8_0;
                let mut vir: *mut u8_0 = virgin as *mut u8_0;
                /* ^WORD_SIZE_64 */
                if *virgin ==
                       0xffffffffffffffff as libc::c_ulong as
                           libc::c_ulonglong ||
                       *cur.offset(0 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(0 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(1 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(1 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(2 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(2 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(3 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(3 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(4 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(4 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(5 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(5 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(6 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(6 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int ||
                       *cur.offset(7 as libc::c_int as isize) as libc::c_int
                           != 0 &&
                           *vir.offset(7 as libc::c_int as isize) as
                               libc::c_int == 0xff as libc::c_int {
                    ret = 1.0f64 as libc::c_float
                } else { ret = 0.5f64 as libc::c_float }
            }
            *virgin &= !*current
        }
        current = current.offset(1);
        virgin = virgin.offset(1)
    }
    printf(b"\x1b[0;35m[D]\x1b[1;90m [src/feedback.c:215] \x1b[0mMAP: %p %lu\x00"
               as *const u8 as *const libc::c_char,
           (*obs_channel).shared_map.map, (*obs_channel).shared_map.map_size);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    let mut j: u32_0 = 0 as libc::c_int as u32_0;
    while (j as libc::c_ulong) < (*obs_channel).shared_map.map_size {
        if *(*obs_channel).shared_map.map.offset(j as isize) != 0 {
            printf(b" %04x=%02x\x00" as *const u8 as *const libc::c_char, j,
                   *(*obs_channel).shared_map.map.offset(j as isize) as
                       libc::c_int);
        }
        j = j.wrapping_add(1)
    }
    printf(b" ret=%f\n\x00" as *const u8 as *const libc::c_char,
           ret as libc::c_double);
    return ret;
}
/* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */
