use ::libc;
extern "C" {
    #[no_mangle]
    fn puts(__s: *const libc::c_char) -> libc::c_int;
    #[no_mangle]
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    #[no_mangle]
    fn exit(_: libc::c_int) -> !;
    #[no_mangle]
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t)
     -> ssize_t;
}
pub type size_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type ssize_t = __ssize_t;
#[no_mangle]
pub static mut file_name: [libc::c_char; 20] =
    unsafe {
        *::std::mem::transmute::<&[u8; 20],
                                 &mut [libc::c_char; 20]>(b"./testcase\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    };
unsafe fn main_0() -> libc::c_int {
    let mut input: [libc::c_char; 100] =
        ['\u{0}' as i32 as libc::c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut r: libc::c_int =
        read(0 as libc::c_int, input.as_mut_ptr() as *mut libc::c_void,
             4 as libc::c_int as size_t) as libc::c_int;
    if r == 0 { puts(b"Error!\n\x00" as *const u8 as *const libc::c_char); }
    printf(b"In target\n\x00" as *const u8 as *const libc::c_char);
    if input[2 as libc::c_int as usize] as libc::c_int == 'B' as i32 ||
           input[2 as libc::c_int as usize] as libc::c_int == 'C' as i32 {
        puts(b"1st block hit\x00" as *const u8 as *const libc::c_char);
        if input[2 as libc::c_int as usize] as libc::c_int == 'C' as i32 {
            puts(b"2nd block hit\x00" as *const u8 as *const libc::c_char);
            ::std::ptr::write_volatile(0 as *mut libc::c_void as
                                           *mut libc::c_int, 0 as libc::c_int)
            // Crash
        }
    }
    exit(0 as libc::c_int);
}
#[main]
pub fn main() { unsafe { ::std::process::exit(main_0() as i32) } }
