use ::libc;
use ::c2rust_asm_casts;
use c2rust_asm_casts::AsmCastTrait;
extern "C" {
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
    #[no_mangle]
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t)
     -> ssize_t;
    #[no_mangle]
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    #[no_mangle]
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn atoi(__nptr: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn select(__nfds: libc::c_int, __readfds: *mut fd_set,
              __writefds: *mut fd_set, __exceptfds: *mut fd_set,
              __timeout: *mut timeval) -> libc::c_int;
    #[no_mangle]
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    #[no_mangle]
    fn free(__ptr: *mut libc::c_void);
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn kill(__pid: __pid_t, __sig: libc::c_int) -> libc::c_int;
    #[no_mangle]
    fn __errno_location() -> *mut libc::c_int;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    #[no_mangle]
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    /* Write sharedmap as env var */
    #[no_mangle]
    fn afl_shmem_to_env_var(shmem: *mut afl_shmem_t,
                            env_name: *mut libc::c_char) -> afl_ret_t;
    // Functions to initialize and deinitialize the generic observation channel. P.S
// You probably will need to extend it the way we've done below.
    #[no_mangle]
    fn afl_observer_init(channel: *mut afl_observer_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_observer_deinit(_: *mut afl_observer_t);
    // Functions to initialize and delete a map based observation channel
    #[no_mangle]
    fn afl_observer_covmap_init(_: *mut afl_observer_covmap_t,
                                map_size: size_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_observer_covmap_deinit(_: *mut afl_observer_covmap_t);
    // "Constructors" and "destructors" for the feedback
    #[no_mangle]
    fn afl_feedback_deinit(_: *mut afl_feedback_t);
    #[no_mangle]
    fn afl_feedback_init(_: *mut afl_feedback_t,
                         queue: *mut afl_queue_feedback_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_feedback_cov_init(feedback: *mut afl_feedback_cov_t,
                             queue: *mut afl_queue_feedback_t,
                             map_observer: *mut afl_observer_covmap_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_feedback_cov_deinit(feedback: *mut afl_feedback_cov_t);
    #[no_mangle]
    fn afl_entry_init(_: *mut afl_entry_t, _: *mut afl_input_t,
                      _: *mut afl_entry_info_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_queue_feedback_init(_: *mut afl_queue_feedback_t,
                               _: *mut afl_feedback_t, _: *mut libc::c_char)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_queue_feedback_deinit(_: *mut afl_queue_feedback_t);
    /* TODO: ADD defualt implementation for the schedule function based on random.
 */
    #[no_mangle]
    fn afl_queue_global_init(_: *mut afl_queue_global_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_queue_global_deinit(_: *mut afl_queue_global_t);
    // Not sure about this functions
                                            // use-case. Was in FFF though.
    #[no_mangle]
    fn afl_engine_init(_: *mut afl_engine_t, _: *mut afl_executor_t,
                       _: *mut afl_fuzz_one_t, _: *mut afl_queue_global_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_engine_deinit(_: *mut afl_engine_t);
    #[no_mangle]
    fn afl_engine_check_configuration(engine: *mut afl_engine_t) -> afl_ret_t;
    /* Add all default mutator funcs */
    #[no_mangle]
    fn afl_mutator_scheduled_add_havoc_funcs(mutator:
                                                 *mut afl_mutator_scheduled_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_mutator_scheduled_init(sched_mut: *mut afl_mutator_scheduled_t,
                                  engine: *mut afl_engine_t,
                                  max_iterations: size_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_mutator_scheduled_deinit(_: *mut afl_mutator_scheduled_t);
    #[no_mangle]
    fn afl_fuzz_one_init(_: *mut afl_fuzz_one_t, _: *mut afl_engine_t)
     -> afl_ret_t;
    #[no_mangle]
    fn afl_fuzz_one_deinit(_: *mut afl_fuzz_one_t);
    #[no_mangle]
    fn afl_stage_init(_: *mut afl_stage_t, _: *mut afl_engine_t) -> afl_ret_t;
    #[no_mangle]
    fn afl_stage_deinit(_: *mut afl_stage_t);
    #[no_mangle]
    fn afl_executor_deinit(_: *mut afl_executor_t);
    #[no_mangle]
    fn fsrv_init(target_path: *mut libc::c_char,
                 extra_target_args: *mut *mut libc::c_char)
     -> *mut afl_forkserver_t;
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
    /* Kicks off all threaded clients in the brackground, using pthreads */
    #[no_mangle]
    fn llmp_broker_launch_clientloops(broker: *mut llmp_broker_t) -> bool;
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
    /* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
    #[no_mangle]
    fn llmp_broker_once(broker: *mut llmp_broker_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __useconds_t = libc::c_uint;
pub type __suseconds_t = libc::c_long;
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
pub type pthread_t = libc::c_ulong;
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
pub type afl_queue_global_t = afl_queue_global;
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
/* Simple MaximizeMapFeedback implementation */
/* Coverage Feedback */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_feedback_cov {
    pub base: afl_feedback_t,
    pub observer_cov: *mut afl_observer_covmap_t,
    pub virgin_bits: *mut u8_0,
    pub size: size_t,
}
pub type afl_feedback_cov_t = afl_feedback_cov;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeout_obs_channel {
    pub base: afl_observer_t,
    pub last_run_time_p: *mut u32_0,
    pub avg_exec_time: u32_0,
}
pub type obs_channel_time_t = timeout_obs_channel;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct time_fbck {
    pub base: afl_feedback_t,
    pub timeout_observer: *mut obs_channel_time_t,
}
pub type time_fbck_t = time_fbck;
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
            current_block_17 = 9381530613075892003;
        }
        4 => { current_block_17 = 9381530613075892003; }
        6 => { current_block_17 = 17808765469879209355; }
        12 => { current_block_17 = 15354265652349651654; }
        _ => {
            return b"Unknown error. Please report this bug!\x00" as *const u8
                       as *const libc::c_char as *mut libc::c_char
        }
    }
    match current_block_17 {
        9381530613075892003 =>
        /* fall-through */
        {
            if *__errno_location() == 0 {
                return b"Error opening file\x00" as *const u8 as
                           *const libc::c_char as *mut libc::c_char
            }
            current_block_17 = 17808765469879209355;
        }
        _ => { }
    }
    match current_block_17 {
        17808765469879209355 =>
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
                   b"../include/alloc-inl.h\x00" as *const u8 as
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
unsafe extern "C" fn afl_argv_cpy_dup(mut argc: libc::c_int,
                                      mut argv: *mut *mut libc::c_char)
 -> *mut *mut libc::c_char {
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut ret: *mut *mut libc::c_char =
        calloc(1 as libc::c_int as libc::c_ulong,
               ((argc + 1 as libc::c_int) as
                    libc::c_ulong).wrapping_mul(::std::mem::size_of::<*mut libc::c_char>()
                                                    as libc::c_ulong)) as
            *mut *mut libc::c_char;
    if ret.is_null() { return 0 as *mut *mut libc::c_char }
    i = 0 as libc::c_int;
    while i < argc {
        let ref mut fresh0 = *ret.offset(i as isize);
        *fresh0 = strdup(*argv.offset(i as isize));
        if (*ret.offset(i as isize)).is_null() {
            let mut k: libc::c_int = 0;
            k = 0 as libc::c_int;
            while k < i {
                free(*ret.offset(k as isize) as *mut libc::c_void);
                k += 1
            }
            free(ret as *mut libc::c_void);
            return 0 as *mut *mut libc::c_char
        }
        i += 1
    }
    let ref mut fresh1 = *ret.offset(i as isize);
    *fresh1 = 0 as *mut libc::c_char;
    return ret;
}
/* This function uses select calls to wait on a child process for given
 * timeout_ms milliseconds and kills it if it doesn't terminate by that time */
#[inline]
unsafe extern "C" fn afl_read_s32_timed(mut fd: s32, mut buf: *mut s32,
                                        mut timeout_ms: u32_0) -> u32_0 {
    let mut readfds: fd_set = fd_set{__fds_bits: [0; 16],};
    let mut __d0: libc::c_int = 0;
    let mut __d1: libc::c_int = 0;
    let fresh2 = &mut __d0;
    let fresh3;
    let fresh4 = &mut __d1;
    let fresh5;
    let fresh6 =
        (::std::mem::size_of::<fd_set>() as
             libc::c_ulong).wrapping_div(::std::mem::size_of::<__fd_mask>() as
                                             libc::c_ulong);
    let fresh7 =
        &mut *readfds.__fds_bits.as_mut_ptr().offset(0 as libc::c_int as
                                                         isize) as
            *mut __fd_mask;
    asm!("cld; rep; stosq" : "={cx}" (fresh3), "={di}" (fresh5) : "{ax}"
         (0 as libc::c_int), "0"
         (c2rust_asm_casts::AsmCast::cast_in(fresh2, fresh6)), "1"
         (c2rust_asm_casts::AsmCast::cast_in(fresh4, fresh7)) : "memory" :
         "volatile");
    c2rust_asm_casts::AsmCast::cast_out(fresh2, fresh6, fresh3);
    c2rust_asm_casts::AsmCast::cast_out(fresh4, fresh7, fresh5);
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
#[inline]
unsafe extern "C" fn afl_observer_delete(mut afl_observer:
                                             *mut afl_observer_t) {
    afl_observer_deinit(afl_observer);
    free(afl_observer as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_observer_covmap_new(mut map_size: size_t)
 -> *mut afl_observer_covmap_t {
    let mut ret: *mut afl_observer_covmap_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_observer_covmap_t>() as
                   libc::c_ulong) as *mut afl_observer_covmap_t;
    if ret.is_null() { return 0 as *mut afl_observer_covmap_t }
    if afl_observer_covmap_init(ret, map_size) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_observer_covmap_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_observer_covmap_delete(mut afl_observer_covmap:
                                                    *mut afl_observer_covmap_t) {
    afl_observer_covmap_deinit(afl_observer_covmap);
    free(afl_observer_covmap as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_feedback_delete(mut afl_feedback:
                                             *mut afl_feedback_t) {
    afl_feedback_deinit(afl_feedback);
    free(afl_feedback as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_feedback_cov_new(mut queue:
                                              *mut afl_queue_feedback_t,
                                          mut map_observer:
                                              *mut afl_observer_covmap_t)
 -> *mut afl_feedback_cov_t {
    let mut ret: *mut afl_feedback_cov_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_feedback_cov_t>() as libc::c_ulong)
            as *mut afl_feedback_cov_t;
    if ret.is_null() { return 0 as *mut afl_feedback_cov_t }
    if afl_feedback_cov_init(ret, queue, map_observer) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_feedback_cov_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_feedback_cov_delete(mut afl_feedback_cov:
                                                 *mut afl_feedback_cov_t) {
    afl_feedback_cov_deinit(afl_feedback_cov);
    free(afl_feedback_cov as *mut libc::c_void);
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
#[inline]
unsafe extern "C" fn afl_queue_feedback_new(mut feedback: *mut afl_feedback_t,
                                            mut name: *mut libc::c_char)
 -> *mut afl_queue_feedback_t {
    let mut ret: *mut afl_queue_feedback_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_queue_feedback_t>() as libc::c_ulong)
            as *mut afl_queue_feedback_t;
    if ret.is_null() { return 0 as *mut afl_queue_feedback_t }
    if afl_queue_feedback_init(ret, feedback, name) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_queue_feedback_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_queue_feedback_delete(mut afl_queue_feedback:
                                                   *mut afl_queue_feedback_t) {
    afl_queue_feedback_deinit(afl_queue_feedback);
    free(afl_queue_feedback as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_queue_global_new() -> *mut afl_queue_global_t {
    let mut ret: *mut afl_queue_global_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_queue_global_t>() as libc::c_ulong)
            as *mut afl_queue_global_t;
    if ret.is_null() { return 0 as *mut afl_queue_global_t }
    if afl_queue_global_init(ret) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_queue_global_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_queue_global_delete(mut afl_queue_global:
                                                 *mut afl_queue_global_t) {
    afl_queue_global_deinit(afl_queue_global);
    free(afl_queue_global as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_engine_new(mut executor: *mut afl_executor_t,
                                    mut fuzz_one: *mut afl_fuzz_one_t,
                                    mut global_queue: *mut afl_queue_global_t)
 -> *mut afl_engine_t {
    let mut ret: *mut afl_engine_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_engine_t>() as libc::c_ulong) as
            *mut afl_engine_t;
    if ret.is_null() { return 0 as *mut afl_engine_t }
    if afl_engine_init(ret, executor, fuzz_one, global_queue) as libc::c_uint
           != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_engine_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_engine_delete(mut afl_engine: *mut afl_engine_t) {
    afl_engine_deinit(afl_engine);
    free(afl_engine as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_mutator_scheduled_new(mut engine: *mut afl_engine_t,
                                               mut max_iterations: size_t)
 -> *mut afl_mutator_scheduled_t {
    let mut ret: *mut afl_mutator_scheduled_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_mutator_scheduled_t>() as
                   libc::c_ulong) as *mut afl_mutator_scheduled_t;
    if ret.is_null() { return 0 as *mut afl_mutator_scheduled_t }
    if afl_mutator_scheduled_init(ret, engine, max_iterations) as libc::c_uint
           != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_mutator_scheduled_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_mutator_scheduled_delete(mut afl_mutator_scheduled:
                                                      *mut afl_mutator_scheduled_t) {
    afl_mutator_scheduled_deinit(afl_mutator_scheduled);
    free(afl_mutator_scheduled as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_fuzz_one_new(mut engine: *mut afl_engine_t)
 -> *mut afl_fuzz_one_t {
    let mut ret: *mut afl_fuzz_one_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_fuzz_one_t>() as libc::c_ulong) as
            *mut afl_fuzz_one_t;
    if ret.is_null() { return 0 as *mut afl_fuzz_one_t }
    if afl_fuzz_one_init(ret, engine) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_fuzz_one_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_fuzz_one_delete(mut afl_fuzz_one:
                                             *mut afl_fuzz_one_t) {
    afl_fuzz_one_deinit(afl_fuzz_one);
    free(afl_fuzz_one as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_stage_new(mut engine: *mut afl_engine_t)
 -> *mut afl_stage_t {
    let mut ret: *mut afl_stage_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<afl_stage_t>() as libc::c_ulong) as
            *mut afl_stage_t;
    if ret.is_null() { return 0 as *mut afl_stage_t }
    if afl_stage_init(ret, engine) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut afl_stage_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn afl_stage_delete(mut afl_stage: *mut afl_stage_t) {
    afl_stage_deinit(afl_stage);
    free(afl_stage as *mut libc::c_void);
}
#[inline]
unsafe extern "C" fn afl_executor_delete(mut afl_executor:
                                             *mut afl_executor_t) {
    afl_executor_deinit(afl_executor);
    free(afl_executor as *mut libc::c_void);
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
#[no_mangle]
pub static mut llmp_broker: *mut llmp_broker_t =
    0 as *const llmp_broker_t as *mut llmp_broker_t;
#[no_mangle]
pub static mut broker_port: libc::c_int = 0;
/* Initialize this feedback */
#[no_mangle]
pub unsafe extern "C" fn time_fbck_init(mut time_fbck: *mut time_fbck_t,
                                        mut queue: *mut afl_queue_feedback_t,
                                        mut timeout_observer:
                                            *mut obs_channel_time_t)
 -> afl_ret_t {
    let mut err: afl_ret_t = afl_feedback_init(&mut (*time_fbck).base, queue);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"[D] [forking-fuzzer.c:61] AFL_TRY returning error: %s\x00" as
                   *const u8 as *const libc::c_char, afl_ret_stringify(err));
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        return err
    }
    (*time_fbck).base.funcs.is_interesting =
        Some(timeout_fbck_is_interesting as
                 unsafe extern "C" fn(_: *mut afl_feedback_t,
                                      _: *mut afl_executor_t)
                     -> libc::c_float);
    (*time_fbck).timeout_observer = timeout_observer;
    (*time_fbck).base.tag = 0xfeedc10c as libc::c_uint;
    return AFL_RET_SUCCESS;
}
#[no_mangle]
pub unsafe extern "C" fn time_fbck_deinit(mut time_fbck: *mut time_fbck_t) {
    afl_feedback_deinit(&mut (*time_fbck).base);
}
/* Create new and delete functions from init and deinit. */
#[inline]
unsafe extern "C" fn time_fbck_new(mut queue: *mut afl_queue_feedback_t,
                                   mut observer: *mut obs_channel_time_t)
 -> *mut time_fbck_t {
    let mut ret: *mut time_fbck_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<time_fbck_t>() as libc::c_ulong) as
            *mut time_fbck_t;
    if ret.is_null() { return 0 as *mut time_fbck_t }
    if time_fbck_init(ret, queue, observer) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        free(ret as *mut libc::c_void);
        return 0 as *mut time_fbck_t
    }
    return ret;
}
#[inline]
unsafe extern "C" fn time_fbck_delete(mut time_fbck: *mut time_fbck_t) {
    time_fbck_deinit(time_fbck);
    free(time_fbck as *mut libc::c_void);
}
/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */
unsafe extern "C" fn fsrv_run_target_custom(mut fsrv_executor:
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
    memset((*fsrv).trace_bits as *mut libc::c_void, 0 as libc::c_int,
           (*fsrv).map_size as libc::c_ulong);
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
            printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Unable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                       *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"fsrv_run_target_custom\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 103 as libc::c_int);
            printf(b"       OS message : %s\n\x00" as *const u8 as
                       *const libc::c_char, strerror(*__errno_location()));
            exit(1 as libc::c_int);
        } else {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Unable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"fsrv_run_target_custom\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 103 as libc::c_int);
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
            printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Unable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                       *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"fsrv_run_target_custom\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 111 as libc::c_int);
            printf(b"       OS message : %s\n\x00" as *const u8 as
                       *const libc::c_char, strerror(*__errno_location()));
            exit(1 as libc::c_int);
        } else {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Unable to request new process from fork server (OOM?)\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 23],
                                             &[libc::c_char; 23]>(b"fsrv_run_target_custom\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 111 as libc::c_int);
            exit(1 as libc::c_int);
        }
    }
    if (*fsrv).child_pid <= 0 as libc::c_int {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Fork server is misbehaving (OOM?)\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 23],
                                         &[libc::c_char; 23]>(b"fsrv_run_target_custom\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               115 as libc::c_int);
        exit(1 as libc::c_int);
    }
    exec_ms =
        afl_read_s32_timed((*fsrv).fsrv_st_fd, &mut (*fsrv).child_status,
                           (*fsrv).exec_tmout);
    (*fsrv).last_run_time = exec_ms;
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
#[no_mangle]
pub unsafe extern "C" fn timeout_channel_reset(mut obs_channel:
                                                   *mut afl_observer_t) {
    let mut observer_time: *mut obs_channel_time_t =
        obs_channel as *mut obs_channel_time_t;
    *(*observer_time).last_run_time_p = 0 as libc::c_int as u32_0;
}
#[no_mangle]
pub unsafe extern "C" fn timeout_channel_post_exec(mut obs_channel:
                                                       *mut afl_observer_t,
                                                   mut engine:
                                                       *mut afl_engine_t) {
    let mut observer_time: *mut obs_channel_time_t =
        obs_channel as *mut obs_channel_time_t;
    (*observer_time).avg_exec_time =
        ((*observer_time).avg_exec_time.wrapping_add(*(*observer_time).last_run_time_p)
             as libc::c_ulonglong).wrapping_div((*engine).executions) as
            u32_0;
}
/* the is_interesting func for our custom timed feedback channel */
/* Another feedback based on the exec time */
unsafe extern "C" fn timeout_fbck_is_interesting(mut feedback:
                                                     *mut afl_feedback_t,
                                                 mut executor:
                                                     *mut afl_executor_t)
 -> libc::c_float {
    let mut fsrv: *mut afl_forkserver_t = executor as *mut afl_forkserver_t;
    let mut exec_timeout: u32_0 = (*fsrv).exec_tmout;
    let mut time_fbck: *mut time_fbck_t = feedback as *mut time_fbck_t;
    let mut observer_time: *mut obs_channel_time_t =
        (*time_fbck).timeout_observer;
    let mut last_run_time: u32_0 = *(*observer_time).last_run_time_p;
    if last_run_time >= exec_timeout {
        let mut input: *mut afl_input_t =
            (*(*fsrv).base.current_input).funcs.copy.expect("non-null function pointer")((*fsrv).base.current_input);
        if input.is_null() {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error creating a copy of input\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 28],
                                             &[libc::c_char; 28]>(b"timeout_fbck_is_interesting\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 192 as libc::c_int);
            exit(1 as libc::c_int);
        }
        let mut new_entry: *mut afl_entry_t =
            afl_entry_new(input, 0 as *mut afl_entry_info_t);
        (*(*new_entry).info).skip_entry = 1 as libc::c_int as u8_0;
        (*(*feedback).queue).base.funcs.insert.expect("non-null function pointer")(&mut (*(*feedback).queue).base,
                                                                                   new_entry);
        return 0.0f64 as libc::c_float
    } else { return 0.0f64 as libc::c_float };
}
#[no_mangle]
pub unsafe extern "C" fn initialize_engine_instance(mut target_path:
                                                        *mut libc::c_char,
                                                    mut in_dir:
                                                        *mut libc::c_char,
                                                    mut target_args:
                                                        *mut *mut libc::c_char)
 -> *mut afl_engine_t {
    /* We initialize the forkserver we want to use here. */
    let mut fsrv: *mut afl_forkserver_t = fsrv_init(target_path, target_args);
    (*fsrv).base.funcs.run_target_cb =
        Some(fsrv_run_target_custom as
                 unsafe extern "C" fn(_: *mut afl_executor_t) -> afl_exit_t);
    if fsrv.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Could not initialize forkserver!\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               214 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*fsrv).exec_tmout = 10000 as libc::c_int as u32_0;
    (*fsrv).target_args = target_args;
    /* Another timing based observation channel. We initialize here instead of adding an init func. */
    let mut observer_time: *mut obs_channel_time_t =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<obs_channel_time_t>() as libc::c_ulong)
            as *mut obs_channel_time_t;
    if observer_time.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing observation channel\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               220 as libc::c_int);
        exit(1 as libc::c_int);
    }
    afl_observer_init(&mut (*observer_time).base);
    (*observer_time).base.funcs.post_exec =
        Some(timeout_channel_post_exec as
                 unsafe extern "C" fn(_: *mut afl_observer_t,
                                      _: *mut afl_engine_t) -> ());
    (*observer_time).base.funcs.reset =
        Some(timeout_channel_reset as
                 unsafe extern "C" fn(_: *mut afl_observer_t) -> ());
    (*observer_time).base.tag = 0xb5ec10c as libc::c_int as u32_0;
    /* The observer directly observes the run_time of the forkserver */
    (*observer_time).last_run_time_p = &mut (*fsrv).last_run_time;
    /* Add to the executor */
    (*fsrv).base.funcs.observer_add.expect("non-null function pointer")(&mut (*fsrv).base,
                                                                        &mut (*observer_time).base);
    /* Let's now create a simple map-based observation channel */
    let mut trace_bits_channel: *mut afl_observer_covmap_t =
        afl_observer_covmap_new(((1 as libc::c_int) << 16 as libc::c_int) as
                                    size_t);
    (*fsrv).base.funcs.observer_add.expect("non-null function pointer")(&mut (*fsrv).base,
                                                                        &mut (*trace_bits_channel).base);
    afl_shmem_to_env_var(&mut (*trace_bits_channel).shared_map,
                         b"__AFL_SHM_ID\x00" as *const u8 as
                             *const libc::c_char as *mut libc::c_char);
    (*fsrv).trace_bits = (*trace_bits_channel).shared_map.map;
    /* We create a simple feedback queue for coverage here*/
    let mut coverage_feedback_queue: *mut afl_queue_feedback_t =
        afl_queue_feedback_new(0 as *mut afl_feedback_t,
                               b"Coverage feedback queue\x00" as *const u8 as
                                   *const libc::c_char as *mut libc::c_char);
    if coverage_feedback_queue.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing feedback queue\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               239 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* Another feedback queue for timeout entries here */
    let mut timeout_feedback_queue: *mut afl_queue_feedback_t =
        afl_queue_feedback_new(0 as *mut afl_feedback_t,
                               b"Timeout feedback queue\x00" as *const u8 as
                                   *const libc::c_char as *mut libc::c_char);
    if timeout_feedback_queue.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing feedback queue\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               243 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* Global queue creation */
    let mut global_queue: *mut afl_queue_global_t = afl_queue_global_new();
    if global_queue.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing global queue\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               247 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*global_queue).funcs.add_feedback_queue.expect("non-null function pointer")(global_queue,
                                                                                 coverage_feedback_queue);
    (*global_queue).funcs.add_feedback_queue.expect("non-null function pointer")(global_queue,
                                                                                 timeout_feedback_queue);
    /* Coverage Feedback initialization */
    let mut coverage_feedback: *mut afl_feedback_cov_t =
        afl_feedback_cov_new(coverage_feedback_queue, trace_bits_channel);
    if coverage_feedback.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing feedback\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               253 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*coverage_feedback_queue).feedback = &mut (*coverage_feedback).base;
    /* Timeout Feedback initialization */
    let mut timeout_feedback: *mut time_fbck_t =
        time_fbck_new(timeout_feedback_queue, observer_time);
    /* Let's build an engine now */
    let mut engine: *mut afl_engine_t =
        afl_engine_new(fsrv as *mut afl_executor_t, 0 as *mut afl_fuzz_one_t,
                       global_queue);
    (*engine).in_dir = in_dir;
    if engine.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing Engine\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               262 as libc::c_int);
        exit(1 as libc::c_int);
    }
    (*engine).funcs.add_feedback.expect("non-null function pointer")(engine,
                                                                     &mut (*coverage_feedback).base);
    (*engine).funcs.add_feedback.expect("non-null function pointer")(engine,
                                                                     &mut (*timeout_feedback).base);
    let mut fuzz_one: *mut afl_fuzz_one_t = afl_fuzz_one_new(engine);
    if fuzz_one.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing fuzz_one\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               267 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut mutators_havoc: *mut afl_mutator_scheduled_t =
        afl_mutator_scheduled_new(engine, 8 as libc::c_int as size_t);
    if mutators_havoc.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error initializing Mutators\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               270 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut err: afl_ret_t =
        afl_mutator_scheduled_add_havoc_funcs(mutators_havoc);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"[D] [forking-fuzzer.c:273] AFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error adding mutators: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               273 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut stage: *mut afl_stage_t = afl_stage_new(engine);
    if stage.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error creating fuzzing stage\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               276 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut err_0: afl_ret_t =
        (*stage).funcs.add_mutator_to_stage.expect("non-null function pointer")(stage,
                                                                                &mut (*mutators_havoc).base);
    if err_0 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        printf(b"[D] [forking-fuzzer.c:278] AFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err_0));
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error adding mutator: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err_0));
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 27],
                                         &[libc::c_char; 27]>(b"initialize_engine_instance\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               278 as libc::c_int);
        exit(1 as libc::c_int);
    }
    return engine;
}
#[no_mangle]
pub unsafe extern "C" fn fuzzer_process_main_forking(mut client: *mut llmp_client_t,
                                             mut data: *mut libc::c_void) {
    let mut engine: *mut afl_engine_t = data as *mut afl_engine_t;
    let mut time_fbck: *mut time_fbck_t = 0 as *mut time_fbck_t;
    let mut coverage_feedback: *mut afl_feedback_cov_t =
        0 as *mut afl_feedback_cov_t;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        match (**(*engine).feedbacks.offset(i as isize)).tag {
            4276994316 => {
                time_fbck =
                    *(*engine).feedbacks.offset(i as isize) as
                        *mut time_fbck_t
            }
            4276994296 => {
                coverage_feedback =
                    *(*engine).feedbacks.offset(i as isize) as
                        *mut afl_feedback_cov_t
            }
            _ => {
                printf(b"[!] WARNING: Found unknown feeback tag: %X\x00" as
                           *const u8 as *const libc::c_char,
                       (**(*engine).feedbacks.offset(i as isize)).tag);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
            }
        }
        i = i.wrapping_add(1)
    }
    let mut fsrv: *mut afl_forkserver_t =
        (*engine).executor as *mut afl_forkserver_t;
    let mut observer_time: *mut obs_channel_time_t =
        0 as *mut obs_channel_time_t;
    let mut observer_covmap: *mut afl_observer_covmap_t =
        0 as *mut afl_observer_covmap_t;
    i = 0 as libc::c_int as size_t;
    while i < (*fsrv).base.observors_count as libc::c_ulong {
        match (**(*engine).feedbacks.offset(i as isize)).tag {
            190759166 => {
                observer_covmap =
                    *(*fsrv).base.observors.offset(i as isize) as
                        *mut afl_observer_covmap_t
            }
            190759180 => {
                observer_time =
                    *(*fsrv).base.observors.offset(i as isize) as
                        *mut obs_channel_time_t
            }
            _ => {
                printf(b"[!] WARNING: Found unknown feeback tag: %X\x00" as
                           *const u8 as *const libc::c_char,
                       (**(*engine).feedbacks.offset(i as isize)).tag);
                printf(b"\n\x00" as *const u8 as *const libc::c_char);
            }
        }
        i = i.wrapping_add(1)
    }
    (*engine).llmp_client = client;
    let mut stage: *mut afl_stage_t =
        *(*(*engine).fuzz_one).stages.offset(0 as libc::c_int as isize);
    let mut mutators_havoc: *mut afl_mutator_scheduled_t =
        *(*stage).mutators.offset(0 as libc::c_int as isize) as
            *mut afl_mutator_scheduled_t;
    /* Let's reduce the timeout initially to fill the queue */
    (*fsrv).exec_tmout = 20 as libc::c_int as u32_0;
    /* Check for engine to be configured properly */
    if afl_engine_check_configuration(engine) as libc::c_uint !=
           AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Engine configured incompletely\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               341 as libc::c_int);
        exit(1 as libc::c_int);
    }
    /* Now we can simply load the testcases from the directory given */
    let mut err: afl_ret_t =
        (*engine).funcs.load_testcases_from_dir.expect("non-null function pointer")(engine,
                                                                                    (*engine).in_dir);
    if err as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint {
        printf(b"[D] [forking-fuzzer.c:344] AFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        fflush(stdout);
        printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Error loading testcase dir: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err));
        printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               344 as libc::c_int);
        printf(b"       OS message : %s\n\x00" as *const u8 as
                   *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    printf(b"[+] Processed %llu input files.\x00" as *const u8 as
               *const libc::c_char, (*engine).executions);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    let mut err_0: afl_ret_t =
        (*engine).funcs.loop_0.expect("non-null function pointer")(engine);
    if err_0 as libc::c_uint != AFL_RET_SUCCESS as libc::c_int as libc::c_uint
       {
        printf(b"[D] [forking-fuzzer.c:348] AFL_TRY returning error: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err_0));
        printf(b"\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        fflush(stdout);
        printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Error fuzzing the target: %s\x00"
                   as *const u8 as *const libc::c_char,
               afl_ret_stringify(err_0));
        printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 20],
                                         &[libc::c_char; 20]>(b"fuzzer_process_main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               348 as libc::c_int);
        printf(b"       OS message : %s\n\x00" as *const u8 as
                   *const libc::c_char, strerror(*__errno_location()));
        exit(1 as libc::c_int);
    }
    printf(b"Fuzzing ends with all the queue entries fuzzed. No of executions %llu\n\x00"
               as *const u8 as *const libc::c_char, (*engine).executions);
    /* Let's free everything now. Note that if you've extended any structure,
   * which now contains pointers to any dynamically allocated region, you have
   * to free them yourselves, but the extended structure itself can be de
   * initialized using the deleted functions provided */
    afl_executor_delete(&mut (*fsrv).base);
    time_fbck_delete(time_fbck);
    afl_feedback_cov_delete(coverage_feedback);
    afl_observer_covmap_delete(observer_covmap);
    afl_observer_delete(&mut (*observer_time).base);
    afl_mutator_scheduled_delete(mutators_havoc);
    afl_stage_delete(stage);
    afl_fuzz_one_delete((*engine).fuzz_one);
    i = 0 as libc::c_int as size_t;
    while (i as libc::c_ulonglong) < (*engine).feedbacks_count {
        afl_feedback_delete(*(*engine).feedbacks.offset(i as isize));
        i = i.wrapping_add(1)
    }
    i = 0 as libc::c_int as size_t;
    while i < (*(*engine).global_queue).feedback_queues_count {
        afl_queue_feedback_delete(*(*(*engine).global_queue).feedback_queues.offset(i
                                                                                        as
                                                                                        isize));
        i = i.wrapping_add(1)
    }
    afl_queue_global_delete((*engine).global_queue);
    afl_engine_delete(engine);
}
#[no_mangle]
pub unsafe extern "C" fn run_broker_thread(mut data: *mut libc::c_void)
 -> *mut libc::c_void {
    llmp_broker_run(llmp_broker);
    return 0 as *mut libc::c_void;
}
/* Main entry point function */
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char)
 -> libc::c_int {
    if argc < 4 as libc::c_int {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Usage: ./forking-fuzzer /input/directory number_of_threads target [target_args]\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               398 as libc::c_int);
        exit(1 as libc::c_int);
    }
    let mut in_dir: *mut libc::c_char =
        *argv.offset(1 as libc::c_int as isize);
    let mut target_path: *mut libc::c_char =
        *argv.offset(3 as libc::c_int as isize);
    let mut thread_count: libc::c_int =
        atoi(*argv.offset(2 as libc::c_int as isize));
    /* A global array of all the registered engines */
    let mut registered_fuzz_workers: *mut *mut afl_engine_t =
        0 as *mut *mut afl_engine_t;
    let mut fuzz_workers_count: u64_0 = 0 as libc::c_int as u64_0;
    if thread_count <= 0 as libc::c_int {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Number of threads should be greater than 0\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               410 as libc::c_int);
        exit(1 as libc::c_int);
    }
    // Time for llmp POC :)
    broker_port = 0xaf1 as libc::c_int;
    llmp_broker = llmp_broker_new();
    if llmp_broker.is_null() {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Broker creation failed\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               415 as libc::c_int);
        exit(1 as libc::c_int);
    }
    if !llmp_broker_register_local_server(llmp_broker, broker_port) {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Broker register failed\x00" as
                   *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               416 as libc::c_int);
        exit(1 as libc::c_int);
    }
    printf(b"[+] Broker created now\x00" as *const u8 as *const libc::c_char);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < thread_count {
        let mut target_args: *mut *mut libc::c_char =
            afl_argv_cpy_dup(argc, argv);
        if target_args.is_null() {
            fflush(stdout);
            printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Error allocating args\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                       *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 423 as libc::c_int);
            printf(b"       OS message : %s\n\x00" as *const u8 as
                       *const libc::c_char, strerror(*__errno_location()));
            exit(1 as libc::c_int);
        }
        let mut engine: *mut afl_engine_t =
            initialize_engine_instance(target_path, in_dir, target_args);
        if !llmp_broker_register_threaded_clientloop(llmp_broker,
                                                     Some(fuzzer_process_main_forking
                                                              as
                                                              unsafe extern "C" fn(_:
                                                                                       *mut llmp_client_t,
                                                                                   _:
                                                                                       *mut libc::c_void)
                                                                  -> ()),
                                                     engine as
                                                         *mut libc::c_void) {
            printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error registering client\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8
                       as *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 429 as libc::c_int);
            exit(1 as libc::c_int);
        }
        fuzz_workers_count = fuzz_workers_count.wrapping_add(1);
        registered_fuzz_workers =
            afl_realloc(registered_fuzz_workers as *mut libc::c_void,
                        fuzz_workers_count.wrapping_mul(::std::mem::size_of::<*mut afl_engine_t>()
                                                            as libc::c_ulong
                                                            as
                                                            libc::c_ulonglong)
                            as size_t) as *mut *mut afl_engine_t;
        if registered_fuzz_workers.is_null() {
            fflush(stdout);
            printf(b"\x1b[?25h\n[-]  SYSTEM ERROR : Could not allocated mem for fuzzer\x00"
                       as *const u8 as *const libc::c_char);
            printf(b"\n    Stop location : %s(), %s:%u\n\x00" as *const u8 as
                       *const libc::c_char,
                   (*::std::mem::transmute::<&[u8; 5],
                                             &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
                   b"forking-fuzzer.c\x00" as *const u8 as
                       *const libc::c_char, 435 as libc::c_int);
            printf(b"       OS message : %s\n\x00" as *const u8 as
                       *const libc::c_char, strerror(*__errno_location()));
            exit(1 as libc::c_int);
        }
        let ref mut fresh8 =
            *registered_fuzz_workers.offset(fuzz_workers_count.wrapping_sub(1
                                                                                as
                                                                                libc::c_int
                                                                                as
                                                                                libc::c_ulonglong)
                                                as isize);
        *fresh8 = engine;
        i += 1
    }
    let mut time_elapsed: u64_0 = 1 as libc::c_int as u64_0;
    if !llmp_broker_launch_clientloops(llmp_broker) {
        printf(b"\x1b[?25h\n[-] PROGRAM ABORT : Error running broker clientloops\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\n         Location : %s(), %s:%u\n\n\x00" as *const u8 as
                   *const libc::c_char,
               (*::std::mem::transmute::<&[u8; 5],
                                         &[libc::c_char; 5]>(b"main\x00")).as_ptr(),
               b"forking-fuzzer.c\x00" as *const u8 as *const libc::c_char,
               442 as libc::c_int);
        exit(1 as libc::c_int);
    }
    printf(b"[+] Broker started running\x00" as *const u8 as
               *const libc::c_char);
    printf(b"\n\x00" as *const u8 as *const libc::c_char);
    loop  {
        llmp_broker_once(llmp_broker);
        usleep(500 as libc::c_int as __useconds_t);
        let mut execs: u64_0 = 0 as libc::c_int as u64_0;
        let mut crashes: u64_0 = 0 as libc::c_int as u64_0;
        let mut i_0: size_t = 0 as libc::c_int as size_t;
        while (i_0 as libc::c_ulonglong) < fuzz_workers_count {
            // TODO: As in-mem-fuzzer
            execs =
                (execs as
                     libc::c_ulonglong).wrapping_add((**registered_fuzz_workers.offset(i_0
                                                                                           as
                                                                                           isize)).executions)
                    as u64_0 as u64_0;
            crashes =
                (crashes as
                     libc::c_ulonglong).wrapping_add((**registered_fuzz_workers.offset(i_0
                                                                                           as
                                                                                           isize)).crashes)
                    as u64_0 as u64_0;
            i_0 = i_0.wrapping_add(1)
        }
        printf(b"Execs: %8llu\tCrashes: %4llu\tExecs per second: %5llu  time elapsed: %8llu\r\x00"
                   as *const u8 as *const libc::c_char, execs, crashes,
               execs.wrapping_div(time_elapsed), time_elapsed);
        time_elapsed = time_elapsed.wrapping_add(1);
        fflush(0 as *mut FILE);
    };
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
