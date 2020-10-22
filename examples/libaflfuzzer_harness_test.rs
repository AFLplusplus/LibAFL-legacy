use ::libc;
extern "C" {
    #[no_mangle]
    static mut stdout: *mut _IO_FILE;
    #[no_mangle]
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn abort() -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
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
pub type uint8_t = __uint8_t;
/* An in memeory fuzzing example. tests segfault, timeout and abort. */
unsafe extern "C" fn force_segfault() {
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer-harness-test.c:9] \x1b[0mCrashing...\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    /* If you don't segfault, what else will? */
    printf(b"%d\x00" as *const u8 as *const libc::c_char,
           *(1337 as libc::c_int as
                 *mut libc::c_int).offset(42 as libc::c_int as isize));
}
unsafe extern "C" fn force_timeout() {
    printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer-harness-test.c:17] \x1b[0mTimeouting...\x00"
               as *const u8 as *const libc::c_char);
    printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
    fflush(stdout);
    static mut a: libc::c_int = 1337 as libc::c_int;
    while a != 0 { };
}
/* The actual harness. Using PNG for our example. */
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerTestOneInput2(mut input: *const uint8_t,
                                                mut len: size_t)
 -> libc::c_int {
    if len < 5 as libc::c_int as libc::c_ulong { return 0 as libc::c_int }
    if *input.offset(0 as libc::c_int as isize) as libc::c_int == 'a' as i32
           &&
           *input.offset(1 as libc::c_int as isize) as libc::c_int ==
               'a' as i32 &&
           *input.offset(2 as libc::c_int as isize) as libc::c_int ==
               'a' as i32 {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer-harness-test.c:30] \x1b[0mCrashing happy\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        force_segfault();
    }
    if *input.offset(0 as libc::c_int as isize) as libc::c_int == 'b' as i32
           &&
           *input.offset(1 as libc::c_int as isize) as libc::c_int ==
               'b' as i32 &&
           *input.offset(2 as libc::c_int as isize) as libc::c_int ==
               'b' as i32 {
        printf(b"\x1b[0;35m[D]\x1b[1;90m [examples/libaflfuzzer-harness-test.c:37] \x1b[0mTimeouting happy\x00"
                   as *const u8 as *const libc::c_char);
        printf(b"\x1b[0m\n\x00" as *const u8 as *const libc::c_char);
        fflush(stdout);
        force_timeout();
    }
    if *input.offset(0 as libc::c_int as isize) as libc::c_int == 'F' as i32 {
        if *input.offset(1 as libc::c_int as isize) as libc::c_int ==
               'A' as i32 {
            if *input.offset(2 as libc::c_int as isize) as libc::c_int ==
                   '$' as i32 {
                if *input.offset(3 as libc::c_int as isize) as libc::c_int ==
                       '$' as i32 {
                    if *input.offset(4 as libc::c_int as isize) as libc::c_int
                           == '$' as i32 {
                        abort();
                    }
                }
            }
        }
    }
    return 0 as libc::c_int;
}
