#[no_mangle]
pub extern "C" fn rust_crypto_init() {
    println!("Rust crypto core initialized");
}

#[no_mangle]
pub extern "C" fn rust_constant_time_compare(a: *const u8, b: *const u8, len: usize) -> u8 {
    let slice_a = unsafe { std::slice::from_raw_parts(a, len) };
    let slice_b = unsafe { std::slice::from_raw_parts(b, len) };
    let mut result: u8 = 0;
    for i in 0..len {
        result |= slice_a[i] ^ slice_b[i];
    }
    (result == 0) as u8
}

#[no_mangle]
pub extern "C" fn rust_secure_zero(ptr: *mut u8, len: usize) {
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
    for byte in slice.iter_mut() {
        *byte = 0;
    }
}
