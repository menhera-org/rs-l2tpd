// Complementary instantiations cover both source arms without covering both per copy.
#[inline(never)]
fn choose<T>(value: bool) -> usize {
    if std::hint::black_box(value) {
        std::mem::size_of::<T>()
    } else {
        0
    }
}

fn main() {
    assert_eq!(choose::<u8>(true), 1);
    assert_eq!(choose::<u16>(false), 0);
    if std::env::args().any(|arg| arg == "both") {
        assert_eq!(choose::<u8>(false), 0);
        assert_eq!(choose::<u16>(true), 2);
    }
}
