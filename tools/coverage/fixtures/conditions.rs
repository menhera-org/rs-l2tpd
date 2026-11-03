#![feature(coverage_attribute)]
use std::hint::black_box;

#[inline(never)]
fn choose<T>(value: bool) -> u8 {
    if black_box((value, std::mem::size_of::<T>())).0 {
        1
    } else {
        2
    }
}

enum Event {
    A,
    B,
    C,
}

#[inline(never)]
fn repeated(event: Event, enabled: bool) -> u8 {
    match event {
        Event::A | Event::B if black_box(enabled) => 1,
        _ => 2,
    }
}

#[coverage(off)]
fn main() {
    let mode = std::env::args().nth(1).unwrap();
    match mode.as_str() {
        "complementary" | "missing-repeated" => {
            assert_eq!(choose::<u8>(true), 1);
            assert_eq!(choose::<u16>(false), 2);
        }
        "both" => {
            for value in [false, true] {
                assert_eq!(choose::<u8>(value), if value { 1 } else { 2 });
                assert_eq!(choose::<u16>(value), if value { 1 } else { 2 });
            }
        }
        "missing-arm" => {
            assert_eq!(choose::<u8>(true), 1);
            assert_eq!(choose::<u16>(true), 1);
        }
        _ => panic!("unexpected calibration mode"),
    }
    if mode == "missing-repeated" {
        assert_eq!(repeated(Event::A, true), 1);
        assert_eq!(repeated(Event::B, false), 2);
    } else {
        for enabled in [false, true] {
            assert_eq!(repeated(Event::A, enabled), if enabled { 1 } else { 2 });
            assert_eq!(repeated(Event::B, enabled), if enabled { 1 } else { 2 });
        }
    }
    assert_eq!(repeated(Event::C, false), 2);
}
