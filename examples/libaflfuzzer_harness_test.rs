use ::libc;
extern "C" {
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn abort() -> !;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
/* An in memeory fuzzing example. tests segfault, timeout and abort. */
unsafe extern "C" fn force_segfault() {
    /* If you don't segfault, what else will? */
    printf(b"%d\x00" as *const u8 as *const libc::c_char,
           *(1337 as libc::c_int as
                 *mut libc::c_int).offset(42 as libc::c_int as isize));
}
unsafe extern "C" fn force_timeout() {
    static mut a: libc::c_int = 1337 as libc::c_int;
    while a != 0 { };
}
/* c2rust always expects this here */
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerInitialize(mut argc: *mut libc::c_int,
                                              mut argv:
                                                  *mut *mut *mut libc::c_char)
 -> libc::c_int {
    return 0 as libc::c_int;
}
/* The actual harness. Using PNG for our example. */
#[no_mangle]
pub unsafe extern "C" fn LLVMFuzzerTestOneInput(mut input: *const uint8_t,
                                                mut len: size_t)
 -> libc::c_int {
    if len < 5 as libc::c_int as libc::c_ulong { return 0 as libc::c_int }
    if *input.offset(0 as libc::c_int as isize) as libc::c_int == 'a' as i32
           &&
           *input.offset(1 as libc::c_int as isize) as libc::c_int ==
               'a' as i32 &&
           *input.offset(2 as libc::c_int as isize) as libc::c_int ==
               'a' as i32 {
        force_segfault();
    }
    if *input.offset(0 as libc::c_int as isize) as libc::c_int == 'b' as i32
           &&
           *input.offset(1 as libc::c_int as isize) as libc::c_int ==
               'b' as i32 &&
           *input.offset(2 as libc::c_int as isize) as libc::c_int ==
               'b' as i32 {
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
