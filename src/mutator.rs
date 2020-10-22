use ::libc;
extern "C" {
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
    pub type afl_fuzz_one;
    pub type afl_executor;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    // Returns new buf containing the substring token
    #[no_mangle]
    fn afl_insert_substring(src_buf: *mut u8_0, dest_buf: *mut u8_0,
                            len: size_t, token: *mut libc::c_void,
                            token_len: size_t, offset: size_t)
     -> *mut libc::c_void;
    // Erases remove_len number of bytes from offset
    #[no_mangle]
    fn afl_erase_bytes(buf: *mut u8_0, len: size_t, offset: size_t,
                       remove_len: size_t) -> size_t;
    // Inserts a certain length of a byte value (byte) at offset in buf
    #[no_mangle]
    fn afl_insert_bytes(src_buf: *mut u8_0, dest_buf: *mut u8_0, len: size_t,
                        byte: u8_0, insert_len: size_t, offset: size_t)
     -> *mut u8_0;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
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
pub type afl_fuzz_one_t = afl_fuzz_one;
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
pub type afl_engine_t = afl_engine;
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
pub type afl_stage_t = afl_stage;
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
pub struct afl_mutator_scheduled {
    pub base: afl_mutator_t,
    pub mutations: *mut afl_mutator_func,
    pub mutators_count: size_t,
    pub funcs: afl_mutator_scheduled_funcs,
    pub max_iterations: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_mutator_scheduled_funcs {
    pub schedule: Option<unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t)
                             -> size_t>,
    pub add_func: Option<unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t,
                                              _: afl_mutator_func)
                             -> afl_ret_t>,
    pub add_default_funcs: Option<unsafe extern "C" fn(_:
                                                           *mut afl_mutator_scheduled_t)
                                      -> afl_ret_t>,
    pub get_iters: Option<unsafe extern "C" fn(_:
                                                   *mut afl_mutator_scheduled_t)
                              -> size_t>,
}
pub type afl_mutator_scheduled_t = afl_mutator_scheduled;
pub type afl_mutator_func
    =
    Option<unsafe extern "C" fn(_: *mut afl_mutator_t, _: *mut afl_input_t)
               -> ()>;
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
/* get the next random number */
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
/* get a random int below the given int (exclusive) */
#[inline]
unsafe extern "C" fn afl_rand_below(mut rnd: *mut afl_rand_t,
                                    mut limit: u64_0) -> u64_0 {
    if limit <= 1 as libc::c_int as libc::c_ulonglong {
        return 0 as libc::c_int as u64_0
    }
    /* The boundary not being necessarily a power of 2,
     we need to ensure the result uniformity. */
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
    /* Modulo is biased - we don't want our fuzzing to be biased so let's do it
  right. See
  https://stackoverflow.com/questions/10984974/why-do-people-say-there-is-modulo-bias-when-using-a-random-number-generator
  */
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
/* A random number between min and max, both inclusive */
#[inline]
unsafe extern "C" fn afl_rand_between(mut rand: *mut afl_rand_t,
                                      mut min: u64_0, mut max: u64_0)
 -> u64_0 {
    return min.wrapping_add(afl_rand_below(rand,
                                           max.wrapping_sub(min).wrapping_add(1
                                                                                  as
                                                                                  libc::c_int
                                                                                  as
                                                                                  libc::c_ulonglong)));
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
pub unsafe extern "C" fn afl_mutator_init(mut mutator: *mut afl_mutator_t,
                                          mut engine: *mut afl_engine_t)
 -> afl_ret_t {
    (*mutator).engine = engine;
    (*mutator).mutate_buf = 0 as *mut u8_0;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutator_deinit(mut mutator: *mut afl_mutator_t) {
    (*mutator).engine = 0 as *mut afl_engine_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutator_scheduled_init(mut sched_mut:
                                                        *mut afl_mutator_scheduled_t,
                                                    mut engine:
                                                        *mut afl_engine_t,
                                                    mut max_iterations:
                                                        size_t) -> afl_ret_t {
    let mut err: afl_ret_t = afl_mutator_init(&mut (*sched_mut).base, engine);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        return err
    }
    (*sched_mut).base.funcs.mutate =
        Some(afl_mutate_scheduled_mutator as
                 unsafe extern "C" fn(_: *mut afl_mutator_t,
                                      _: *mut afl_input_t) -> size_t);
    (*sched_mut).funcs.add_func =
        Some(afl_mutator_add_func as
                 unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t,
                                      _: afl_mutator_func) -> afl_ret_t);
    (*sched_mut).funcs.get_iters =
        Some(afl_iterations as
                 unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t)
                     -> size_t);
    (*sched_mut).funcs.schedule =
        Some(afl_schedule as
                 unsafe extern "C" fn(_: *mut afl_mutator_scheduled_t)
                     -> size_t);
    (*sched_mut).max_iterations =
        if max_iterations > 0 as libc::c_int as libc::c_ulong {
            max_iterations
        } else { 7 as libc::c_int as libc::c_ulong };
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutator_scheduled_deinit(mut sched_mut:
                                                          *mut afl_mutator_scheduled_t) {
    let mut i: size_t = 0;
    afl_mutator_deinit(&mut (*sched_mut).base);
    (*sched_mut).max_iterations = 0 as libc::c_int as size_t;
    i = 0 as libc::c_int as size_t;
    while i < (*sched_mut).mutators_count {
        let ref mut fresh1 = *(*sched_mut).mutations.offset(i as isize);
        *fresh1 = None;
        i = i.wrapping_add(1)
    }
    afl_free((*sched_mut).mutations as *mut libc::c_void);
    (*sched_mut).mutations = 0 as *mut afl_mutator_func;
    (*sched_mut).mutators_count = 0 as libc::c_int as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutator_add_func(mut mutator:
                                                  *mut afl_mutator_scheduled_t,
                                              mut mutator_func:
                                                  afl_mutator_func)
 -> afl_ret_t {
    (*mutator).mutators_count = (*mutator).mutators_count.wrapping_add(1);
    (*mutator).mutations =
        afl_realloc((*mutator).mutations as *mut libc::c_void,
                    (*mutator).mutators_count.wrapping_mul(::std::mem::size_of::<afl_mutator_func>()
                                                               as
                                                               libc::c_ulong))
            as *mut afl_mutator_func;
    if (*mutator).mutations.is_null() {
        (*mutator).mutators_count = 0 as libc::c_int as size_t;
        return AFL_RET_ALLOC
    }
    let ref mut fresh2 =
        *(*mutator).mutations.offset((*mutator).mutators_count.wrapping_sub(1
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                libc::c_ulong)
                                         as isize);
    *fresh2 = mutator_func;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn afl_iterations(mut mutator:
                                            *mut afl_mutator_scheduled_t)
 -> size_t {
    return ((1 as libc::c_int) <<
                (1 as libc::c_int as
                     libc::c_ulonglong).wrapping_add(afl_rand_below(&mut (*(*mutator).base.engine).rand,
                                                                    (*mutator).max_iterations
                                                                        as
                                                                        u64_0)))
               as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_schedule(mut mutator:
                                          *mut afl_mutator_scheduled_t)
 -> size_t {
    return afl_rand_below(&mut (*(*mutator).base.engine).rand,
                          (*mutator).mutators_count as u64_0) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutate_scheduled_mutator(mut mutator:
                                                          *mut afl_mutator_t,
                                                      mut input:
                                                          *mut afl_input_t)
 -> size_t {
    // This is to stop from compiler complaining about the incompatible pointer
  // type for the function ptrs. We need a better solution for this to pass the
  // scheduled_mutator rather than the mutator as an argument.
    let mut scheduled_mutator: *mut afl_mutator_scheduled_t =
        mutator as *mut afl_mutator_scheduled_t;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i <
              (*scheduled_mutator).funcs.get_iters.expect("non-null function pointer")(scheduled_mutator)
          {
        (*(*scheduled_mutator).mutations.offset((*scheduled_mutator).funcs.schedule.expect("non-null function pointer")(scheduled_mutator)
                                                    as
                                                    isize)).expect("non-null function pointer")(&mut (*scheduled_mutator).base,
                                                                                                input);
        i = i.wrapping_add(1)
    }
    return 0 as libc::c_int as size_t;
}
/* A few simple mutators that we use over in AFL++ in the havoc and
 * deterministic modes*/
unsafe extern "C" fn choose_block_len(mut rand: *mut afl_rand_t,
                                      mut limit: size_t) -> size_t {
    let mut min_value: size_t = 0;
    let mut max_value: size_t = 0;
    match afl_rand_below(rand, 3 as libc::c_int as u64_0) {
        0 => {
            min_value = 1 as libc::c_int as size_t;
            max_value = 32 as libc::c_int as size_t
        }
        1 => {
            min_value = 32 as libc::c_int as size_t;
            max_value = 128 as libc::c_int as size_t
        }
        _ => {
            if afl_rand_below(rand, 10 as libc::c_int as u64_0) != 0 {
                min_value = 128 as libc::c_int as size_t;
                max_value = 1500 as libc::c_int as size_t
            } else {
                min_value = 1500 as libc::c_int as size_t;
                max_value = 32768 as libc::c_int as size_t
            }
        }
    }
    if min_value >= limit { min_value = 1 as libc::c_int as size_t }
    return afl_rand_between(rand, min_value as u64_0,
                            ({
                                 let mut _a: size_t = max_value;
                                 let mut _b: size_t = limit;
                                 if _a < _b { _a } else { _b }
                             }) as u64_0) as size_t;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutfunc_flip_bit(mut mutator: *mut afl_mutator_t,
                                              mut input: *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut bit: libc::c_int =
        afl_rand_below(rand,
                       (*input).len.wrapping_mul(8 as libc::c_int as
                                                     libc::c_ulong).wrapping_sub(1
                                                                                     as
                                                                                     libc::c_int
                                                                                     as
                                                                                     libc::c_ulong)
                           as
                           u64_0).wrapping_add(1 as libc::c_int as
                                                   libc::c_ulonglong) as
            libc::c_int;
    let ref mut fresh3 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh3 =
        (*fresh3 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutfunc_flip_2_bits(mut mutator:
                                                     *mut afl_mutator_t,
                                                 mut input:
                                                     *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    let mut bit: libc::c_int =
        afl_rand_below(rand,
                       size.wrapping_mul(8 as libc::c_int as
                                             libc::c_ulong).wrapping_sub(1 as
                                                                             libc::c_int
                                                                             as
                                                                             libc::c_ulong)
                           as
                           u64_0).wrapping_add(1 as libc::c_int as
                                                   libc::c_ulonglong) as
            libc::c_int;
    if (size << 3 as libc::c_int).wrapping_sub(bit as libc::c_ulong) <
           2 as libc::c_int as libc::c_ulong {
        return
    }
    let ref mut fresh4 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh4 =
        (*fresh4 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
    bit += 1;
    let ref mut fresh5 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh5 =
        (*fresh5 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutfunc_flip_4_bits(mut mutator:
                                                     *mut afl_mutator_t,
                                                 mut input:
                                                     *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size <= 0 as libc::c_int as libc::c_ulong { return }
    let mut bit: libc::c_int =
        afl_rand_below(rand,
                       (size <<
                            3 as
                                libc::c_int).wrapping_sub(1 as libc::c_int as
                                                              libc::c_ulong)
                           as
                           u64_0).wrapping_add(1 as libc::c_int as
                                                   libc::c_ulonglong) as
            libc::c_int;
    if (size << 3 as libc::c_int).wrapping_sub(bit as libc::c_ulong) <
           4 as libc::c_int as libc::c_ulong {
        return
    }
    let ref mut fresh6 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh6 =
        (*fresh6 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
    bit += 1;
    let ref mut fresh7 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh7 =
        (*fresh7 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
    bit += 1;
    let ref mut fresh8 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh8 =
        (*fresh8 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
    bit += 1;
    let ref mut fresh9 =
        *(*input).bytes.offset((bit >> 3 as libc::c_int) as isize);
    *fresh9 =
        (*fresh9 as libc::c_int ^
             (1 as libc::c_int) <<
                 (bit - 1 as libc::c_int) % 8 as libc::c_int) as u8_0;
}
#[inline]
unsafe extern "C" fn afl_mutfunc_flip_byte(mut mutator: *mut afl_mutator_t,
                                           mut input: *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size <= 0 as libc::c_int as libc::c_ulong { return }
    let mut byte: libc::c_int =
        afl_rand_below(rand, size as u64_0) as libc::c_int;
    let ref mut fresh10 = *(*input).bytes.offset(byte as isize);
    *fresh10 = (*fresh10 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
}
#[inline]
unsafe extern "C" fn afl_mutfunc_flip_2_bytes(mut mutator: *mut afl_mutator_t,
                                              mut input: *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size < 2 as libc::c_int as libc::c_ulong { return }
    let mut byte: libc::c_int =
        afl_rand_below(rand,
                       size.wrapping_sub(1 as libc::c_int as libc::c_ulong) as
                           u64_0) as libc::c_int;
    let ref mut fresh11 = *(*input).bytes.offset(byte as isize);
    *fresh11 = (*fresh11 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
    let ref mut fresh12 =
        *(*input).bytes.offset((byte + 1 as libc::c_int) as isize);
    *fresh12 = (*fresh12 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
}
#[inline]
unsafe extern "C" fn afl_mutfunc_flip_4_bytes(mut mutator: *mut afl_mutator_t,
                                              mut input: *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size < 4 as libc::c_int as libc::c_ulong { return }
    let mut byte: libc::c_int =
        afl_rand_below(rand,
                       size.wrapping_sub(3 as libc::c_int as libc::c_ulong) as
                           u64_0) as libc::c_int;
    if byte == -(1 as libc::c_int) { return }
    let ref mut fresh13 = *(*input).bytes.offset(byte as isize);
    *fresh13 = (*fresh13 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
    let ref mut fresh14 =
        *(*input).bytes.offset((byte + 1 as libc::c_int) as isize);
    *fresh14 = (*fresh14 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
    let ref mut fresh15 =
        *(*input).bytes.offset((byte + 2 as libc::c_int) as isize);
    *fresh15 = (*fresh15 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
    let ref mut fresh16 =
        *(*input).bytes.offset((byte + 3 as libc::c_int) as isize);
    *fresh16 = (*fresh16 as libc::c_int ^ 0xff as libc::c_int) as u8_0;
}
#[inline]
unsafe extern "C" fn afl_mutfunc_random_byte_add_sub(mut mutator:
                                                         *mut afl_mutator_t,
                                                     mut input:
                                                         *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size <= 0 as libc::c_int as libc::c_ulong { return }
    let mut idx: size_t = afl_rand_below(rand, size as u64_0) as size_t;
    let ref mut fresh17 = *(*input).bytes.offset(idx as isize);
    *fresh17 =
        (*fresh17 as libc::c_int -
             (1 as libc::c_int +
                  afl_rand_below(rand, 35 as libc::c_int as u64_0) as u8_0 as
                      libc::c_int)) as u8_0;
    let ref mut fresh18 = *(*input).bytes.offset(idx as isize);
    *fresh18 =
        (*fresh18 as libc::c_int +
             (1 as libc::c_int +
                  afl_rand_below(rand, 35 as libc::c_int as u64_0) as u8_0 as
                      libc::c_int)) as u8_0;
}
#[inline]
unsafe extern "C" fn afl_mutfunc_random_byte(mut mutator: *mut afl_mutator_t,
                                             mut input: *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size <= 0 as libc::c_int as libc::c_ulong { return }
    let mut idx: libc::c_int =
        afl_rand_below(rand, size as u64_0) as libc::c_int;
    let ref mut fresh19 = *(*input).bytes.offset(idx as isize);
    *fresh19 =
        (*fresh19 as libc::c_int ^
             1 as libc::c_int +
                 afl_rand_below(rand, 255 as libc::c_int as u64_0) as u8_0 as
                     libc::c_int) as u8_0;
}
#[inline]
unsafe extern "C" fn afl_mutfunc_delete_bytes(mut mutator: *mut afl_mutator_t,
                                              mut input: *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size < 2 as libc::c_int as libc::c_ulong { return }
    let mut del_len: size_t =
        choose_block_len(rand,
                         size.wrapping_sub(1 as libc::c_int as
                                               libc::c_ulong));
    let mut del_from: size_t =
        afl_rand_below(rand,
                       size.wrapping_sub(del_len).wrapping_add(1 as
                                                                   libc::c_int
                                                                   as
                                                                   libc::c_ulong)
                           as u64_0) as size_t;
    /* We delete the bytes and then update the new input length*/
    (*input).len = afl_erase_bytes((*input).bytes, size, del_from, del_len);
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutfunc_clone_bytes(mut mutator:
                                                     *mut afl_mutator_t,
                                                 mut input:
                                                     *mut afl_input_t) {
    if (*input).len == 0 { return }
    let mut rand: *mut afl_rand_t = &mut (*(*mutator).engine).rand;
    let mut size: size_t = (*input).len;
    if size == 0 { return }
    let mut actually_clone: libc::c_int =
        afl_rand_below(rand, 4 as libc::c_int as u64_0) as libc::c_int;
    let mut clone_from: size_t = 0;
    let mut clone_to: size_t = 0;
    let mut clone_len: size_t = 0;
    clone_to = afl_rand_below(rand, size as u64_0) as size_t;
    if actually_clone != 0 {
        clone_len = choose_block_len(rand, size);
        clone_from =
            afl_rand_below(rand,
                           size.wrapping_sub(clone_len).wrapping_add(1 as
                                                                         libc::c_int
                                                                         as
                                                                         libc::c_ulong)
                               as u64_0) as size_t;
        (*mutator).mutate_buf =
            afl_realloc((*mutator).mutate_buf as *mut libc::c_void,
                        clone_len.wrapping_add(size)) as *mut u8_0;
        (*input).bytes =
            afl_insert_substring((*input).bytes, (*mutator).mutate_buf, size,
                                 (*input).bytes.offset(clone_from as isize) as
                                     *mut libc::c_void, clone_len, clone_to)
                as *mut u8_0;
        (*input).len =
            ((*input).len as libc::c_ulong).wrapping_add(clone_len) as size_t
                as size_t
    } else {
        clone_len = choose_block_len(rand, 32768 as libc::c_int as size_t);
        (*input).bytes =
            afl_insert_bytes((*input).bytes, (*mutator).mutate_buf, size,
                             afl_rand_below(rand, 255 as libc::c_int as u64_0)
                                 as u8_0, clone_len, clone_to);
        (*input).len =
            ((*input).len as libc::c_ulong).wrapping_add(clone_len) as size_t
                as size_t
    };
}
unsafe extern "C" fn locate_diffs(mut ptr1: *mut u8_0, mut ptr2: *mut u8_0,
                                  mut len: u32_0, mut first: *mut s32,
                                  mut last: *mut s32) {
    let mut f_loc: s32 = -(1 as libc::c_int);
    let mut l_loc: s32 = -(1 as libc::c_int);
    let mut pos: u32_0 = 0;
    pos = 0 as libc::c_int as u32_0;
    while pos < len {
        let fresh20 = ptr1;
        ptr1 = ptr1.offset(1);
        let fresh21 = ptr2;
        ptr2 = ptr2.offset(1);
        if *fresh20 as libc::c_int != *fresh21 as libc::c_int {
            if f_loc == -(1 as libc::c_int) { f_loc = pos as s32 }
            l_loc = pos as s32
        }
        pos = pos.wrapping_add(1)
    }
    *first = f_loc;
    *last = l_loc;
}
#[no_mangle]
pub unsafe extern "C" fn afl_mutfunc_splice(mut mutator: *mut afl_mutator_t,
                                            mut input: *mut afl_input_t) {
    /* Let's grab the engine for random num generation and queue */
    if (*input).len == 0 {
        return
    } // +1 so that we can also grab a queue
                                                                                 // entry from the global_queue
    let mut engine: *mut afl_engine_t = (*mutator).engine;
    let mut global_queue: *mut afl_queue_global_t = (*engine).global_queue;
    let mut splice_input: *mut afl_input_t = 0 as *mut afl_input_t;
    let mut f_diff: s32 = 0 as libc::c_int;
    let mut l_diff: s32 = 0 as libc::c_int;
    let mut counter: libc::c_int = 0 as libc::c_int;
    loop  {
        let mut random_queue_idx: size_t =
            afl_rand_below(&mut (*engine).rand,
                           (*global_queue).feedback_queues_count.wrapping_add(1
                                                                                  as
                                                                                  libc::c_int
                                                                                  as
                                                                                  libc::c_ulong)
                               as u64_0) as size_t;
        if random_queue_idx < (*global_queue).feedback_queues_count {
            // Grab a random entry from the random feedback queue
            let mut random_fbck_queue: *mut afl_queue_feedback_t =
                *(*global_queue).feedback_queues.offset(random_queue_idx as
                                                            isize);
            splice_input =
                if (*random_fbck_queue).base.entries_count >
                       0 as libc::c_int as libc::c_ulong {
                    (**(*random_fbck_queue).base.entries.offset(afl_rand_below(&mut (*engine).rand,
                                                                               (*random_fbck_queue).base.entries_count
                                                                                   as
                                                                                   u64_0)
                                                                    as
                                                                    isize)).input
                } else { 0 as *mut afl_input_t };
            if !splice_input.is_null() && (*splice_input).bytes.is_null() {
                splice_input = 0 as *mut afl_input_t
            }
        } else {
            // Grab a random entry from the global queue
            splice_input =
                if (*global_queue).base.entries_count >
                       0 as libc::c_int as libc::c_ulong {
                    (**(*global_queue).base.entries.offset(afl_rand_below(&mut (*engine).rand,
                                                                          (*global_queue).base.entries_count
                                                                              as
                                                                              u64_0)
                                                               as
                                                               isize)).input
                } else { 0 as *mut afl_input_t };
            if !splice_input.is_null() && (*splice_input).bytes.is_null() {
                splice_input = 0 as *mut afl_input_t
            }
        }
        // Counter basically stops it from infinite loop in case of empty queue
        let fresh22 = counter;
        counter = counter + 1;
        if fresh22 > 20 as libc::c_int { return }
        if !splice_input.is_null() {
            locate_diffs((*input).bytes, (*splice_input).bytes,
                         ({
                              let mut _a: s64 = (*input).len as s64;
                              let mut _b: s64 = (*splice_input).len as s64;
                              if _a < _b { _a } else { _b }
                          }) as u32_0, &mut f_diff, &mut l_diff);
        }
        if !(f_diff < 0 as libc::c_int || l_diff < 2 as libc::c_int ||
                 f_diff == l_diff) {
            break ;
        }
    }
    /* Split somewhere between the first and last differing byte. */
    let mut split_at: u32_0 =
        (f_diff as
             libc::c_ulonglong).wrapping_add(afl_rand_below(&mut (*engine).rand,
                                                            (l_diff - f_diff)
                                                                as u64_0)) as
            u32_0;
    /* Do the thing. */
    (*input).len = (*splice_input).len;
    /* Let's use the mutate_buf for splicing */
    (*mutator).mutate_buf =
        afl_realloc((*mutator).mutate_buf as *mut libc::c_void, (*input).len)
            as *mut u8_0;
    memcpy((*mutator).mutate_buf as *mut libc::c_void,
           (*input).bytes as *const libc::c_void, split_at as libc::c_ulong);
    (*input).bytes = (*mutator).mutate_buf;
    memcpy((*input).bytes.offset(split_at as isize) as *mut libc::c_void,
           (*splice_input).bytes.offset(split_at as isize) as
               *const libc::c_void,
           (*splice_input).len.wrapping_sub(split_at as libc::c_ulong));
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
// The params here are in_buf and out_buf.
// Mutate function
// Checks if the queue entry is to be fuzzed or not
// Post process API AFL++
// Extra buf for mutators to work with for afl_realloc
// A simple scheduled mutator based on the above mutator. Will act something
// similar to the havoc stage
// A ptr to an array of mutation operator
                                // functions
/* TODO add implementation for the _schedule_ and _iterations_ functions, need a
 * random list element pop type implementation for this */
/* Add a mutator func to this mutators */
/* Add all default mutator funcs */
#[no_mangle]
pub unsafe extern "C" fn afl_mutator_scheduled_add_havoc_funcs(mut mutator:
                                                                   *mut afl_mutator_scheduled_t)
 -> afl_ret_t {
    let mut err: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_flip_byte
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        return err
    }
    let mut err_0: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_flip_2_bytes
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_0 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_0
    }
    let mut err_1: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_flip_4_bytes
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_1 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_1
    }
    let mut err_2: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_delete_bytes
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_2 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_2
    }
    let mut err_3: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_clone_bytes
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_3 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_3
    }
    let mut err_4: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_flip_bit
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_4 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_4
    }
    let mut err_5: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_flip_2_bits
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_5 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_5
    }
    let mut err_6: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_flip_4_bits
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_6 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_6
    }
    let mut err_7: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_random_byte_add_sub
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_7 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_7
    }
    let mut err_8: afl_ret_t =
        (*mutator).funcs.add_func.expect("non-null function pointer")(mutator,
                                                                      Some(afl_mutfunc_random_byte
                                                                               as
                                                                               unsafe extern "C" fn(_:
                                                                                                        *mut afl_mutator_t,
                                                                                                    _:
                                                                                                        *mut afl_input_t)
                                                                                   ->
                                                                                       ()));
    if err_8 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        return err_8
    }
    return AFL_RET_SUCCESS;
}
