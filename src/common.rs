use ::libc;
extern "C" {
    pub type __dirstream;
    #[no_mangle]
    fn opendir(__name: *const libc::c_char) -> *mut DIR;
    #[no_mangle]
    fn closedir(__dirp: *mut DIR) -> libc::c_int;
    #[no_mangle]
    fn memmove(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong)
     -> *mut libc::c_void;
    #[no_mangle]
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type __uint8_t = libc::c_uchar;
pub type DIR = __dirstream;
pub type size_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type u8_0 = uint8_t;
/* returns true, if the given dir exists, else false */
#[no_mangle]
pub unsafe extern "C" fn afl_dir_exists(mut dirpath: *mut libc::c_char)
 -> bool {
    let mut dir_in: *mut DIR = 0 as *mut DIR;
    let mut dir_name_size: size_t = strlen(dirpath);
    if *dirpath.offset(dir_name_size.wrapping_sub(1 as libc::c_int as
                                                      libc::c_ulong) as isize)
           as libc::c_int == '/' as i32 {
        *dirpath.offset(dir_name_size.wrapping_sub(1 as libc::c_int as
                                                       libc::c_ulong) as
                            isize) = '\u{0}' as i32 as libc::c_char
    }
    dir_in = opendir(dirpath);
    if dir_in.is_null() { return 0 as libc::c_int != 0 }
    closedir(dir_in);
    return 1 as libc::c_int != 0;
}
/* Few helper functions */
#[no_mangle]
pub unsafe extern "C" fn afl_insert_substring(mut src_buf: *mut u8_0,
                                              mut dest_buf: *mut u8_0,
                                              mut len: size_t,
                                              mut token: *mut libc::c_void,
                                              mut token_len: size_t,
                                              mut offset: size_t)
 -> *mut libc::c_void {
    // void *new_buf = calloc(len + token_len + 1, 1);
    memmove(dest_buf as *mut libc::c_void, src_buf as *const libc::c_void,
            offset);
    memmove(dest_buf.offset(offset as isize) as *mut libc::c_void, token,
            token_len);
    memmove(dest_buf.offset(offset as isize).offset(token_len as isize) as
                *mut libc::c_void,
            src_buf.offset(offset as isize) as *const libc::c_void,
            len.wrapping_sub(offset));
    return dest_buf as *mut libc::c_void;
}
// Inserts a certain length of a byte value (byte) at offset in buf
/* This function inserts given number of bytes at a certain offset in a string
  and returns a ptr to the newly allocated memory. NOTE: You have to free the
  original memory(if malloced) yourself*/
#[no_mangle]
pub unsafe extern "C" fn afl_insert_bytes(mut src_buf: *mut u8_0,
                                          mut dest_buf: *mut u8_0,
                                          mut len: size_t, mut byte: u8_0,
                                          mut insert_len: size_t,
                                          mut offset: size_t) -> *mut u8_0 {
    memmove(dest_buf as *mut libc::c_void, src_buf as *const libc::c_void,
            offset);
    memset(dest_buf.offset(offset as isize) as *mut libc::c_void,
           byte as libc::c_int, insert_len);
    memmove(dest_buf.offset(offset as isize).offset(insert_len as isize) as
                *mut libc::c_void,
            src_buf.offset(offset as isize) as *const libc::c_void,
            len.wrapping_sub(offset));
    return dest_buf;
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
// Returns new buf containing the substring token
// Erases remove_len number of bytes from offset
#[no_mangle]
pub unsafe extern "C" fn afl_erase_bytes(mut buf: *mut u8_0, mut len: size_t,
                                         mut offset: size_t,
                                         mut remove_len: size_t) -> size_t {
    memmove(buf.offset(offset as isize) as *mut libc::c_void,
            buf.offset(offset as isize).offset(remove_len as isize) as
                *const libc::c_void,
            len.wrapping_sub(offset).wrapping_sub(remove_len));
    memset(buf.offset(len as isize).offset(-(remove_len as isize)) as
               *mut libc::c_void, 0 as libc::c_int, remove_len);
    let mut new_size: size_t = len.wrapping_sub(remove_len);
    return new_size;
}
