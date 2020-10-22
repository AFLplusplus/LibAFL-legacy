use ::libc;
extern "C" {
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...)
     -> libc::c_int;
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
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
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    /* Creates a new client process that will connect to the given port */
    #[no_mangle]
    fn llmp_client_new(port: libc::c_int) -> *mut llmp_client_t;
    /* A client blocks/spins until the next message gets posted to the page,
  then returns that message. */
    #[no_mangle]
    fn llmp_client_recv_blocking(client: *mut llmp_client_t)
     -> *mut llmp_message_t;
    /* Will return a ptr to the next msg buf, potentially mapping a new page automatically, if needed.
Never call alloc_next multiple times without either sending or cancelling the last allocated message for this page!
There can only ever be up to one message allocated per page at each given time. */
    #[no_mangle]
    fn llmp_client_alloc_next(client: *mut llmp_client_t, size: size_t)
     -> *mut llmp_message_t;
    /* Cancels a msg previously allocated by alloc_next.
You can now allocate a new buffer on this page using alloc_next.
Don't write to the msg anymore, and don't send this message! */
    /* Commits a msg to the client's out buf. After this, don't  write to this msg anymore! */
    #[no_mangle]
    fn llmp_client_send(client_state: *mut llmp_client_t,
                        msg: *mut llmp_message_t) -> bool;
    /* Allocate and set up the new broker instance. Afterwards, run with broker_run. */
    #[no_mangle]
    fn llmp_broker_init(broker: *mut llmp_broker_t) -> afl_ret_t;
    /* Client thread will be called with llmp_client_t client, containing the
data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
    #[no_mangle]
    fn llmp_broker_register_threaded_clientloop(broker: *mut llmp_broker_t,
                                                clientloop:
                                                    llmp_clientloop_func,
                                                data: *mut libc::c_void)
     -> bool;
    /* Register a simple tcp client that will listen for new shard map clients via
 tcp */
    #[no_mangle]
    fn llmp_broker_register_local_server(broker: *mut llmp_broker_t,
                                         port: libc::c_int) -> bool;
    /* Start all threads and the main broker.
Same as llmp_broker_launch_threaded clients();
Never returns. */
    #[no_mangle]
    fn llmp_broker_run(broker: *mut llmp_broker_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __useconds_t = libc::c_uint;
pub type __ssize_t = libc::c_long;
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
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type pthread_t = libc::c_ulong;
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
/*TODO: Still need to add a base implementation for this.*/
// AFL_NEW_AND_DELETE_FOR_WITH_PARAMS(afl_queue_feedback, AFL_DECL_PARAMS(afl_feedback_t *feedback, char *name),
//                                   AFL_CALL_PARAMS(feedback, name));
// Default implementations for the functions for queue_entry vtable
/* TODO: Add the base  */
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
// A function which tells how many mutated
                                       // inputs to generate out of a given input
/* Change the void pointer to a mutator * once it is ready */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_stage {
    pub engine: *mut afl_engine_t,
    pub funcs: afl_stage_funcs,
    pub mutators: *mut *mut afl_mutator_t,
    pub mutators_count: size_t,
}
pub type afl_mutator_t = afl_mutator;
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
            current_block_17 = 71504420348896963;
        }
        4 => { current_block_17 = 71504420348896963; }
        6 => { current_block_17 = 10811496654675101; }
        12 => { current_block_17 = 17234009953499979309; }
        _ => {
            return b"Unknown error. Please report this bug!\x00" as *const u8
                       as *const libc::c_char as *mut libc::c_char
        }
    }
    match current_block_17 {
        71504420348896963 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Error opening file\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 10811496654675101;
        }
        _ => { }
    }
    match current_block_17 {
        10811496654675101 =>
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
/* initialize feeded by urandom */
#[inline]
unsafe extern "C" fn afl_rand_init(mut rnd: *mut afl_rand_t) -> afl_ret_t {
    memset(rnd as *mut libc::c_void, 0 as libc::c_int,
           ::std::mem::size_of::<afl_rand_t>() as libc::c_ulong);
    (*rnd).dev_urandom_fd =
        open(b"/dev/urandom\x00" as *const u8 as *const libc::c_char,
             0 as libc::c_int);
    if (*rnd).dev_urandom_fd == 0 { return AFL_RET_FILE_OPEN_ERROR }
    (*rnd).fixed_seed = 0 as libc::c_int != 0;
    /* do one call to rand_below to seed the rng */
    afl_rand_below(rnd, 1 as libc::c_int as u64_0);
    return AFL_RET_SUCCESS;
}
#[inline]
unsafe extern "C" fn llmp_broker_new() -> *mut llmp_broker_t {
    let mut ret: *mut llmp_broker_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<llmp_broker_t>() as libc::c_ulong) as
            *mut llmp_broker_t;
    if ret.is_null() { return 0 as *mut llmp_broker_t }
    if llmp_broker_init(ret) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut llmp_broker_t
    }
    return ret;
}
/* A client that randomly produces messages */
#[no_mangle]
pub unsafe extern "C" fn llmp_clientloop_rand_u32(mut client:
                                                      *mut llmp_client_t,
                                                  mut data:
                                                      *mut libc::c_void) {
    let mut rnd: afl_rand_t =
        {
            let mut init =
                afl_rand{rand_cnt: 0 as libc::c_int as u32_0,
                         rand_seed: [0; 4],
                         dev_urandom_fd: 0,
                         init_seed: 0,
                         fixed_seed: false,};
            init
        };
    let mut err: afl_ret_t = afl_rand_init(&mut rnd);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [llmp-main.c:23] \x1b[0mAFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError creating rnd! %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 25],
                                         &[libc::c_char; 25]>(b"llmp_clientloop_rand_u32\x00")).as_ptr(),
               b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
               23 as libc::c_int);
        exit(1 as libc::c_int);
    }
    loop  {
        let mut msg: *mut llmp_message_t =
            llmp_client_alloc_next(client,
                                   ::std::mem::size_of::<u32_0>() as
                                       libc::c_ulong);
        (*msg).tag = 0x344d011 as libc::c_int as u32_0;
        *((*msg).buf.as_mut_ptr() as
              *mut u32_0).offset(0 as libc::c_int as isize) =
            afl_rand_below(&mut rnd,
                           18446744073709551615 as libc::c_ulong as u64_0) as
                u32_0;
        printf(b"\x1b[1;92m[+] \x1b[0m%d Sending msg with id %d and payload %d.\x00"
                   as *const u8 as *const libc::c_char, (*client).id,
               (*msg).message_id,
               *((*msg).buf.as_mut_ptr() as
                     *mut u32_0).offset(0 as libc::c_int as isize));
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        llmp_client_send(client, msg);
        usleep(afl_rand_below(&mut rnd,
                              4000 as libc::c_int as
                                  u64_0).wrapping_mul(1000 as libc::c_int as
                                                          libc::c_ulonglong)
                   as __useconds_t);
    };
}
/* A client listening for new messages, then printing them */
#[no_mangle]
pub unsafe extern "C" fn llmp_clientloop_print_u32(mut client_state:
                                                       *mut llmp_client_t,
                                                   mut data:
                                                       *mut libc::c_void) {
    let mut message: *mut llmp_message_t = 0 as *mut llmp_message_t;
    loop  {
        asm!("" : : : "memory" : "volatile");
        message = llmp_client_recv_blocking(client_state);
        if (*message).tag == 0x344d011 as libc::c_int as libc::c_uint {
            if (*message).buf_len_padded <
                   ::std::mem::size_of::<u32_0>() as libc::c_ulong {
                printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mBUG: incorrect buflen size for u32 message type\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                           as *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 26],
                                                 &[libc::c_char; 26]>(b"llmp_clientloop_print_u32\x00")).as_ptr(),
                       b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
                       53 as libc::c_int);
                exit(1 as libc::c_int);
            }
            printf(b"Got a random int from the queue: %d\n\x00" as *const u8
                       as *const libc::c_char,
                   *((*message).buf.as_mut_ptr() as
                         *mut u32_0).offset(0 as libc::c_int as isize));
        }
    };
}
/* Main entry point function */
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    let mut thread_count: libc::c_int = 1 as libc::c_int;
    let mut port: libc::c_int = 0xaf1 as libc::c_int;
    let mut is_main: bool = 1 as libc::c_int != 0;
    if argc < 2 as libc::c_int || argc > 4 as libc::c_int {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mUsage ./llmp_test [main|worker] <thread_count=1> <port=0xAF1>\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
               71 as libc::c_int);
        exit(1 as libc::c_int);
    }
    if strcmp(*argv.offset(1 as libc::c_int as isize),
              b"worker\x00" as *const u8 as *const libc::c_char) == 0 {
        is_main = 0 as libc::c_int != 0
    } else if strcmp(*argv.offset(1 as libc::c_int as isize),
                     b"main\x00" as *const u8 as *const libc::c_char) != 0 {
        printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mMode must either be main or worker!\nUsage ./llmp_test [main|worker] <thread_count=1> <port=0xAF1>\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                   as *const u8 as *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
               81 as libc::c_int);
        exit(1 as libc::c_int);
    }
    if argc > 2 as libc::c_int {
        thread_count = atoi(*argv.offset(2 as libc::c_int as isize));
        if thread_count < 0 as libc::c_int {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mNumber of clients cannot be negative.\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
                   88 as libc::c_int);
            exit(1 as libc::c_int);
        }
        printf(b"\x1b[1;92m[+] \x1b[0mSpawning %d clients\x00" as *const u8 as
                   *const libc::c_char, thread_count);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    }
    if argc > 3 as libc::c_int {
        port = atoi(*argv.offset(2 as libc::c_int as isize));
        if port <= 0 as libc::c_int ||
               port >= (1 as libc::c_int) << 16 as libc::c_int {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0millegal port\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
                   96 as libc::c_int);
            exit(1 as libc::c_int);
        }
    }
    if is_main {
        /* The main node has a broker, a tcp server, and a few worker threads */
        let mut broker: *mut llmp_broker_t = llmp_broker_new();
        llmp_broker_register_local_server(broker, port);
        if !llmp_broker_register_threaded_clientloop(broker,
                                                     Some(llmp_clientloop_print_u32
                                                              as
                                                              unsafe extern "C" fn(_:
                                                                                       *mut llmp_client_t,
                                                                                   _:
                                                                                       *mut libc::c_void)
                                                                  -> ()),
                                                     0 as *mut libc::c_void) {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0merror adding threaded client\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
                   109 as libc::c_int);
            exit(1 as libc::c_int);
        }
        let mut i: libc::c_int = 0;
        i = 0 as libc::c_int;
        while i < thread_count {
            if !llmp_broker_register_threaded_clientloop(broker,
                                                         Some(llmp_clientloop_rand_u32
                                                                  as
                                                                  unsafe extern "C" fn(_:
                                                                                           *mut llmp_client_t,
                                                                                       _:
                                                                                           *mut libc::c_void)
                                                                      -> ()),
                                                         0 as
                                                             *mut libc::c_void)
               {
                printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0merror adding threaded client\x00"
                           as *const u8 as *const libc::c_char);
                printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                           as *const u8 as *const libc::c_char,
                       (*::std::mem::transmute::<&[u8; 5],
                                                 &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                       b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
                       118 as libc::c_int);
                exit(1 as libc::c_int);
            }
            i += 1
        }
        printf(b"\x1b[1;92m[+] \x1b[0mSpawning main on port %d\x00" as
                   *const u8 as *const libc::c_char, port);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        llmp_broker_run(broker);
    } else {
        if thread_count > 1 as libc::c_int {
            printf(b"\x1b[1;93m[!] \x1b[1;97mWARNING: \x1b[0mMultiple threads not supported for clients.\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        }
        printf(b"\x1b[1;92m[+] \x1b[0mClient will connect to port %d\x00" as
                   *const u8 as *const libc::c_char, port);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        // Worker only needs to spawn client threads.
        let mut client_state: *mut llmp_client_t = llmp_client_new(port);
        if client_state.is_null() {
            printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mError connecting to broker at port %d\x00"
                       as *const u8 as *const libc::c_char, port);
            printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00"
                       as *const u8 as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
                   134 as libc::c_int);
            exit(1 as libc::c_int);
        }
        llmp_clientloop_rand_u32(client_state, 0 as *mut libc::c_void);
    }
    printf(b"\x0f\x1b)B\x1b[?25h\x1b[0m\x1b[1;91m\n[-] PROGRAM ABORT : \x1b[0mUnreachable\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[1;91m\n         Location : \x1b[0m%s(), %s:%u\n\n\x00" as
               *const u8 as *const libc::c_char,
           (*::std::mem::transmute::<&[u8; 5],
                                     &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
           b"llmp-main.c\x00" as *const u8 as *const libc::c_char,
           139 as libc::c_int);
    exit(1 as libc::c_int);
}
#[main]
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(::std::ffi::CString::new(arg).expect("Failed to convert argument into CString.").into_raw());
    };
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0((args.len() - 1) as libc::c_int,
                                    args.as_mut_ptr() as
                                        *mut *mut libc::c_char) as i32)
    }
}
