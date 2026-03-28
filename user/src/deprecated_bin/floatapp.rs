#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("float app begins");
    println!("{:.2} is float number", 2.0 / 3.0);
    0
}
